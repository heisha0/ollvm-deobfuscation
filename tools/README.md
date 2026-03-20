# 二进制分析工具

本目录包含用于 OLLVM 混淆对比分析的工具。

---

## 📦 工具列表

| 文件名 | 用途 |
|--------|------|
| `binary_analyzer.py` | 分析当前 IDA 中打开的二进制文件并生成报告 |
| `compare_analyses.py` | 比较两个分析报告 |

---

## 🚀 使用步骤

### 分析非混淆版本
```bash
python binary_analyzer.py
```

### 分析混淆版本
```bash
python binary_analyzer.py
```

### 对比分析
```bash
python compare_analyses.py report1.json report2.json
```
