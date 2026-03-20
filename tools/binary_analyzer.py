#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最终的 IDA MCP 分析脚本
能够正确处理数据和生成报告
"""

import sys
import json
import subprocess
import tempfile
import os
import datetime

def call_mcp_tool(method_name, params=None):
    """调用 MCP 工具"""
    url = "http://127.0.0.1:13337/mcp"
    request_id = 1

    payload = {
        "jsonrpc": "2.0",
        "method": method_name,
        "params": params or {},
        "id": request_id
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
        json.dump(payload, f)
        temp_path = f.name

    try:
        cmd = [
            'curl', '-s', '-X', 'POST',
            '-H', 'Content-Type: application/json',
            '-d', '@' + temp_path,
            url
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

        if result.returncode != 0:
            print(f"Error: curl failed with {result.returncode}")
            return None

        return json.loads(result.stdout)
    finally:
        os.unlink(temp_path)

def analyze_binary():
    """分析二进制文件"""
    print("=" * 60)
    print("OLLVM 二进制分析工具")
    print("=" * 60)

    # 初始化
    print("\n[1] 初始化 MCP 连接...")
    init_result = call_mcp_tool("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "binary-analyzer", "version": "1.0.0"}
    })

    if not init_result or "error" in init_result:
        print("连接失败！")
        if init_result:
            print(init_result.get("error", {}))
        return None

    server_info = init_result['result']['serverInfo']
    print(f"  已连接到: {server_info['name']} v{server_info['version']}")

    # 获取所有函数
    print("\n[2] 获取函数信息...")
    func_result = call_mcp_tool("tools/call", {
        "name": "list_funcs",
        "arguments": {"queries": {"count": 0}}
    })

    if not func_result or "result" not in func_result:
        print("无法获取函数列表")
        return None

    func_groups = func_result['result']['structuredContent']['result']

    all_functions = []
    total_count = 0
    named_count = 0
    sub_count = 0
    total_size = 0
    max_size = 0

    for func_group in func_groups:
        if 'data' in func_group:
            for func in func_group['data']:
                all_functions.append(func)
                total_count += 1

                name = func.get('name', '')
                size_str = func.get('size', '0x0')
                size = int(size_str, 16)
                total_size += size

                if size > max_size:
                    max_size = size

                if name.startswith('sub_'):
                    sub_count += 1
                elif name:
                    named_count += 1

    avg_size = total_size // total_count if total_count > 0 else 0

    print(f"  总函数数: {total_count}")
    print(f"  有名称函数: {named_count}")
    print(f"  匿名函数: {sub_count}")
    print(f"  总大小: {total_size} 字节")
    print(f"  平均大小: {avg_size} 字节")
    print(f"  最大大小: {max_size} 字节")

    # 搜索特征字节模式
    print("\n[3] 搜索特征字节模式...")
    patterns = [
        "63 7C 77 7B F2 6B 6F C5",  # AES S-Box
        "D6 1F 00 C0",  # br xN (间接跳转)
        "D6 3F 00 C0",  # blr xN (间接跳转)
    ]

    byte_result = call_mcp_tool("tools/call", {
        "name": "find_bytes",
        "arguments": {"patterns": patterns, "limit": 30}
    })

    byte_count = 0
    if byte_result and "result" in byte_result:
        sc = byte_result['result']['structuredContent']
        if 'result' in sc:
            byte_count = len(sc['result'])

    print(f"  找到 {byte_count} 个特征字节模式匹配")

    # 搜索关键字字符串
    print("\n[4] 搜索关键字字符串...")
    keywords = ["AES", "encrypt", "decrypt", "key", "SBox", "cipher"]
    string_matches = 0

    for keyword in keywords:
        str_result = call_mcp_tool("tools/call", {
            "name": "find",
            "arguments": {"type": "string", "targets": [keyword]}
        })

        if str_result and "result" in str_result:
            sc = str_result['result']['structuredContent']
            if 'result' in sc:
                count = len(sc['result'])
                string_matches += count

    print(f"  找到 {string_matches} 个关键字匹配")

    # 搜索间接跳转模式
    print("\n[5] 搜索间接跳转特征...")
    indirect_jumps = 0

    indirect_result = call_mcp_tool("tools/call", {
        "name": "find_bytes",
        "arguments": {"patterns": ["D6 1F 00 C0", "D6 3F 00 C0"], "limit": 50}
    })

    if indirect_result and "result" in indirect_result:
        sc = indirect_result['result']['structuredContent']
        if 'result' in sc:
            indirect_jumps = len(sc['result'])

    print(f"  找到 {indirect_jumps} 个间接跳转指令")

    # 生成报告
    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "server_info": server_info,
        "file_info": {},
        "analysis": {
            "total_functions": total_count,
            "named_functions": named_count,
            "anonymous_functions": sub_count,
            "total_size": total_size,
            "avg_size": avg_size,
            "max_size": max_size,
            "byte_matches": byte_count,
            "string_matches": string_matches,
            "indirect_jumps": indirect_jumps,
        },
        "functions": all_functions
    }

    # 保存报告
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"binary_analysis_{timestamp}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[6] 分析报告已保存到: {filename}")

    return report, filename

def create_summary(report):
    """创建分析摘要"""
    analysis = report['analysis']
    print("=" * 60)
    print("分析摘要")
    print("=" * 60)

    print(f"总函数数: {analysis['total_functions']}")
    print(f"有名称函数: {analysis['named_functions']}")
    print(f"匿名函数: {analysis['anonymous_functions']}")
    print(f"总大小: {analysis['total_size']} 字节")
    print(f"平均大小: {analysis['avg_size']} 字节")
    print(f"最大大小: {analysis['max_size']} 字节")
    print(f"特征字节匹配: {analysis['byte_matches']}")
    print(f"关键字匹配: {analysis['string_matches']}")
    print(f"间接跳转: {analysis['indirect_jumps']}")

def main():
    try:
        report, filename = analyze_binary()
        if report:
            print("")
            create_summary(report)

        print("\n分析完成！")
        return 0
    except Exception as e:
        print(f"分析过程出错: {e}")
        import traceback
        print(traceback.format_exc())
        return 1

if __name__ == "__main__":
    sys.exit(main())
