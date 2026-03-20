#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
比较两个分析报告的脚本
"""

import sys
import json
import os

def load_report(filename):
    """加载报告"""
    if not os.path.exists(filename):
        print(f"错误: 文件 {filename} 不存在")
        return None

    with open(filename, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except Exception as e:
            print(f"加载报告失败: {e}")
            return None

def compare_reports(report1, report2, file1, file2):
    """比较两个报告"""
    print("=" * 60)
    print(f"对比分析: {file1} vs {file2}")
    print("=" * 60)

    print("\n[1] 函数统计对比")
    print("-" * 40)
    print(f"{'指标':<20}{file1:<15}{file2:<15}")
    print("-" * 40)
    print(f"{'总函数数':<20}{report1['analysis']['total_functions']:<15}{report2['analysis']['total_functions']:<15}")
    print(f"{'有名称函数':<20}{report1['analysis']['named_functions']:<15}{report2['analysis']['named_functions']:<15}")
    print(f"{'匿名函数':<20}{report1['analysis']['anonymous_functions']:<15}{report2['analysis']['anonymous_functions']:<15}")
    print(f"{'平均大小':<20}{report1['analysis']['avg_size']:<15}{report2['analysis']['avg_size']:<15}")
    print(f"{'最大大小':<20}{report1['analysis']['max_size']:<15}{report2['analysis']['max_size']:<15}")

    print("\n[2] 特征对比")
    print("-" * 40)
    print(f"{'特征':<20}{file1:<15}{file2:<15}")
    print("-" * 40)
    print(f"{'字节模式':<20}{report1['analysis']['byte_matches']:<15}{report2['analysis']['byte_matches']:<15}")
    print(f"{'关键字':<20}{report1['analysis']['string_matches']:<15}{report2['analysis']['string_matches']:<15}")
    print(f"{'间接跳转':<20}{report1['analysis']['indirect_jumps']:<15}{report2['analysis']['indirect_jumps']:<15}")

    print("\n[3] 比率计算")
    print("-" * 40)
    func_ratio = report2['analysis']['total_functions'] / report1['analysis']['total_functions']
    indirect_ratio = report2['analysis']['indirect_jumps'] / report1['analysis']['indirect_jumps'] if report1['analysis']['indirect_jumps'] > 0 else 0

    print(f"{'函数数量增长':<20}{func_ratio:.2f}x")
    print(f"{'间接跳转增长':<20}{indirect_ratio:.2f}x")

    print("\n" + "=" * 60)

    # 检测混淆特征
    obfuscation_signs = []

    if func_ratio > 2.5:
        obfuscation_signs.append("❌ 函数数量异常增长")
    if indirect_ratio > 5:
        obfuscation_signs.append("❌ 间接跳转显著增加")
    if report2['analysis']['avg_size'] > report1['analysis']['avg_size'] * 1.5:
        obfuscation_signs.append("❌ 平均函数大小变大")

    if obfuscation_signs:
        print("⚠️  检测到的混淆特征:")
        for sign in obfuscation_signs:
            print(f"  {sign}")
    else:
        print("✅ 未检测到典型的 OLLVM 混淆特征")

    return func_ratio, indirect_ratio

def main():
    if len(sys.argv) < 3:
        print("用法: python compare_analyses.py <report1> <report2>")
        print("       python compare_analyses.py binary_analysis_20260319_222603.json binary_analysis_obfuscated.json")
        return 1

    report1 = load_report(sys.argv[1])
    report2 = load_report(sys.argv[2])

    if not report1 or not report2:
        return 1

    func_ratio, indirect_ratio = compare_reports(report1, report2, sys.argv[1], sys.argv[2])

    return 0

if __name__ == "__main__":
    sys.exit(main())
