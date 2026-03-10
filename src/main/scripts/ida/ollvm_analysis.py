#coding=utf-8
"""
OLLVM 分析脚本 - IDA Pro 使用
用于分析和辅助反混淆
"""

import idautils
import idaapi
import idc
import ida_bytes
import ida_name
import ida_segment
import ida_funcs
import ida_xref
import ida_search
import ida_pattern
import ida_ua
import ida_nalt
import ida_diskio

from typing import List, Dict, Tuple, Optional, Set
import struct
import binascii
import re
import os

# === 配置 ===
DEBUG_MODE = False

# === 辅助函数 ===
def log(msg):
    """日志输出"""
    if DEBUG_MODE:
        print(f"[OLLVM] {msg}")

def set_debug(debug):
    """设置调试模式"""
    global DEBUG_MODE
    DEBUG_MODE = debug

def color_func(ea, color):
    """设置函数颜色"""
    func = idaapi.get_func(ea)
    if func:
        ida_funcs.set_func_color(func.start_ea, color)

def format_hex(data):
    """格式化字节为十六进制字符串"""
    return binascii.hexlify(data).decode('ascii')

def is_thumb_mode(ea):
    """检查是否是 Thumb 模式"""
    return (ea & 1) != 0

# === 基础分析函数 ===
def find_strings():
    """查找字符串"""
    log("查找字符串...")
    strings = []

    for string in idautils.Strings():
        if string.length >= 4:
            content = str(string)
            strings.append((string.ea, content))

    log(f"找到 {len(strings)} 个字符串")
    return strings

def find_decrypt_candidates():
    """查找解密函数候选"""
    decrypt_candidates = []

    for func in idautils.Functions():
        func_name = ida_funcs.get_func_name(func)
        if has_decrypt_pattern(func, func_name):
            decrypt_candidates.append((func, func_name))

    log(f"找到 {len(decrypt_candidates)} 个解密函数候选")
    return decrypt_candidates

def has_decrypt_pattern(func_ea, func_name):
    """检查函数是否包含解密模式"""
    patterns = [
        lambda s: 'xor' in s.lower(),
        lambda s: 'decrypt' in s.lower(),
        lambda s: 'goron' in s.lower(),
        lambda s: 'unpack' in s.lower(),
        lambda s: 'deobfuscate' in s.lower()
    ]

    for head in idautils.Heads(func_ea, idaapi.get_func(func_ea).end_ea):
        for check in patterns:
            try:
                if check(idc.print_insn_mnem(head) + ' ' + idc.print_operand(head, 0)):
                    return True
            except:
                continue

    return False

def find_address_tables():
    """查找地址表"""
    address_tables = []

    for seg_ea in idautils.Segments():
        seg_name = idaapi.get_segm_name(seg_ea)
        if seg_name in [".rodata", ".data", ".got"]:
            for offset in idautils.Heads(seg_ea, idaapi.get_segm_end(seg_ea)):
                try:
                    qword = ida_bytes.get_qword(offset)
                    if qword != 0:
                        seg = idaapi.getseg(qword)
                        if seg and seg.name == ".text":
                            address_tables.append((offset, qword))
                except:
                    continue

    return address_tables

# === 字符串加密分析 ===
def analyze_string_encryption():
    """分析字符串加密"""
    log("开始分析字符串加密...")

    strings = find_strings()
    candidates = find_decrypt_candidates()

    log("字符串加密分析完成")
    return strings, candidates

# === 间接跳转分析 ===
def find_indirect_jumps():
    """查找间接跳转"""
    jumps = []

    for func in idautils.Functions():
        for head in idautils.Heads(func, idaapi.get_func(func).end_ea):
            try:
                mnemonic = idc.print_insn_mnem(head)

                if is_thumb_mode(func):
                    if (mnemonic == 'bx' or mnemonic == 'blx') and idc.print_operand(head, 0).startswith('r'):
                        jumps.append((func, head, mnemonic))
                else:
                    if (mnemonic == 'br' or mnemonic == 'blr') and idc.print_operand(head, 0).startswith('x'):
                        jumps.append((func, head, mnemonic))

            except Exception as e:
                continue

    return jumps

def analyze_indirect_jumps():
    """分析间接跳转"""
    log("开始分析间接跳转...")

    jumps = find_indirect_jumps()

    for func_ea, jump_ea, mnem in jumps:
        func_name = ida_funcs.get_func_name(func_ea)

        log(f"发现 {mnem} @ 0x{jump_ea:x} in {func_name}")

        # 查找地址表
        tables = find_address_tables_near(jump_ea)
        for table in tables:
            log(f"  找到地址表 @ 0x{table:x}")

        color_func(func_ea, 0xFF0000)  # 红色标记

    log(f"找到 {len(jumps)} 个间接跳转")
    return jumps

def find_address_tables_near(jump_ea, range=0x100):
    """查找跳转附近的地址表"""
    tables = []
    start = max(0, jump_ea - range)
    end = jump_ea + range

    for offset in range(start, end):
        try:
            qword = ida_bytes.get_qword(offset)
            if qword != 0:
                seg = idaapi.getseg(qword)
                if seg and seg.name == ".text":
                    tables.append(offset)
        except Exception as e:
            continue

    return tables

# === 实用工具 ===
def export_strings():
    """导出字符串到 JSON"""
    strings = find_strings()

    data = []
    for ea, content in strings:
        refs = []
        for xref in idautils.XrefsTo(ea):
            refs.append(xref.frm)

        data.append({
            "address": hex(ea),
            "content": content,
            "xrefs": [hex(x) for x in refs]
        })

    return data

def export_analysis():
    """导出完整分析结果"""
    strings, candidates = analyze_string_encryption()
    jumps = analyze_indirect_jumps()

    report = {
        "strings": [
            {
                "address": hex(ea),
                "content": str(content),
                "xrefs": [hex(x.frm) for x in idautils.XrefsTo(ea)]
            }
            for ea, content in strings
        ],
        "decrypt_candidates": [
            {
                "address": hex(ea),
                "name": name
            }
            for ea, name in candidates
        ],
        "indirect_jumps": [
            {
                "address": hex(ea),
                "mnem": str(mnem),
                "function": hex(func),
                "function_name": ida_funcs.get_func_name(func)
            }
            for func, ea, mnem in jumps
        ],
        "address_tables": [
            {
                "address": hex(ea),
                "points_to": hex(qword)
            }
            for ea, qword in find_address_tables()
        ]
    }

    return report

def save_report(data, filename=None):
    """保存分析报告"""
    import json

    if filename is None:
        filename = "ollvm_analysis_report.json"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        log(f"报告已保存到 {filename}")
        return True
    except Exception as e:
        log(f"保存报告失败: {e}")
        return False

def auto_naming():
    """自动命名"""
    for func, func_name in find_decrypt_candidates():
        if not func_name.startswith('sub_'):
            continue

        # 为解密函数候选重命名
        index = len(idautils.Strings())
        ida_name.set_name(func, f"decrypt_candidate_{index}", ida_name.SN_CHECK)

    log("自动命名完成")

def make_functions():
    """创建未识别的函数"""
    log("创建未识别的函数...")

    start = idaapi.get_first_seg().start_ea
    end = idaapi.get_last_seg().end_ea

    added = 0

    for ea in range(start, end, 4):
        if idaapi.get_func(ea) is None and idc.print_insn_mnem(ea) in ["push", "stp"]:
            try:
                ida_funcs.add_func(ea)
                added += 1
            except Exception as e:
                log(f"创建函数失败: {e}")

    log(f"创建了 {added} 个函数")

def analyze_xrefs(ea):
    """分析交叉引用"""
    log(f"分析 {hex(ea)} 的交叉引用...")

    xrefs_to = list(idautils.XrefsTo(ea))
    xrefs_from = list(idautils.XrefsFrom(ea))

    log(f"    引用数量: {len(xrefs_to)}")

    for xref in xrefs_to:
        log(f"      来自函数: {ida_funcs.get_func_name(xref.frm)} ({hex(xref.frm)})")

    return xrefs_to, xrefs_from

def analyze_memory_access():
    """分析内存访问"""
    log("分析内存访问...")

    memory_access = []

    for func in idautils.Functions():
        func_name = ida_funcs.get_func_name(func)

        for head in idautils.Heads(func, idaapi.get_func(func).end_ea):
            try:
                mnem = idc.print_insn_mnem(head)
                op_str = idc.print_operand(head, 0)

                if "ldr" in mnem or "str" in mnem or "mov" in mnem:
                    if '[' in op_str and ']' in op_str:
                        memory_access.append((func, head, mnem, op_str))

            except Exception as e:
                continue

    log(f"找到 {len(memory_access)} 个内存访问")
    return memory_access

def detect_x86_patterns():
    """检测 x86 特定模式"""
    patterns = []

    # 查找常见的 XOR 模式
    for func in idautils.Functions():
        has_xor = False
        has_loop = False

        for head in idautils.Heads(func, idaapi.get_func(func).end_ea):
            try:
                if idc.print_insn_mnem(head) == "xor":
                    has_xor = True

                if idc.print_insn_mnem(head) in ["loop", "jmp", "jne"]:
                    has_loop = True

            except Exception as e:
                continue

        if has_xor and has_loop:
            patterns.append(func)

    log(f"找到 {len(patterns)} 个可能的解密函数")
    return patterns

def list_imports():
    """列出导入函数"""
    imports = []

    for seg in idautils.Segments():
        seg_name = idaapi.get_segm_name(seg)
        if seg_name in [".import", "idata"]:
            for offset in idautils.Heads(seg, idaapi.get_segm_end(seg)):
                try:
                    name = ida_nalt.get_name(offset)
                    if name:
                        imports.append((offset, name))
                except Exception as e:
                    continue

    return imports

def list_exports():
    """列出导出函数"""
    exports = []

    for seg in idautils.Segments():
        seg_name = idaapi.get_segm_name(seg)
        if seg_name in [".export", "edata"]:
            for offset in idautils.Heads(seg, idaapi.get_segm_end(seg)):
                try:
                    name = ida_nalt.get_name(offset)
                    if name:
                        exports.append((offset, name))
                except Exception as e:
                    continue

    return exports

# === 主函数 ===
def main():
    """主函数"""
    print("=" * 60)
    print("OLLVM 分析脚本")
    print("=" * 60)
    print()

    set_debug(True)

    print("1. 基础分析")
    print("2. 字符串加密分析")
    print("3. 间接跳转分析")
    print("4. 完整分析")
    print("5. 导出报告")
    print("6. 自动命名")
    print()

    try:
        choice = input("选择操作 (1-6): ").strip()

        if choice == '1':
            log("基础分析:")

            log(f"函数数量: {len(list(idautils.Functions()))}")
            log(f"字符串数量: {len(list(idautils.Strings()))}")

            for func, name in find_decrypt_candidates():
                log(f"  候选函数: {hex(func)} - {name}")

            for ea, qword in find_address_tables():
                log(f"  地址表: {hex(ea)} -> {hex(qword)}")

        elif choice == '2':
            strings, candidates = analyze_string_encryption()

            print(f"找到 {len(strings)} 个字符串")
            for ea, content in strings[:5]:
                print(f"  0x{ea:x}: '{content}'")

            print(f"找到 {len(candidates)} 个解密候选")
            for func, name in candidates:
                print(f"  0x{func:x}: '{name}'")

        elif choice == '3':
            jumps = analyze_indirect_jumps()

            print(f"找到 {len(jumps)} 个间接跳转")
            for func, ea, mnem in jumps:
                func_name = ida_funcs.get_func_name(func)
                print(f"  0x{ea:x}: '{mnem}' in '{func_name}'")

        elif choice == '4':
            data = export_analysis()

            print(f"字符串: {len(data['strings'])}")
            print(f"解密候选: {len(data['decrypt_candidates'])}")
            print(f"间接跳转: {len(data['indirect_jumps'])}")
            print(f"地址表: {len(data['address_tables'])}")

            save_report(data)

        elif choice == '5':
            data = export_analysis()
            save_report(data)
            print(f"报告已保存到 ollvm_analysis_report.json")

        elif choice == '6':
            auto_naming()
            print("自动命名完成")

        else:
            print("无效选择")

    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

    print()
    print("操作完成")

if __name__ == "__main__":
    main()