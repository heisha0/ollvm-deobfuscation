# OLLVM 反混淆项目

## 📌 项目概述
- 目标：基于 unidbg 的 OLLVM 反混淆工具
- 平台：ARM64 Android SO 文件
- 语言：Java 8 + Maven
- 当前阶段：第一阶 - 间接跳转反混淆

## 🏗️ 项目结构
```
ollvm-deobfuscation/
├── deobfuscation-core/    # 核心反混淆库
│   └── src/main/java/com/ollvm/
│       ├── Main.java             # CLI 入口
│       ├── indirectjump/         # 间接跳转反混淆
│       │   └── UnidbgIndirectJumpDeobfuscator.java
│       ├── stringencryption/     # 字符串解密
│       │   └── UnidbgStringDecryptor.java
│       └── utils/              # 工具类
│           └── XorDecryptor.java
└── unidbg-wrapper/          # Unidbg 封装
```

## 📚 依赖
- Unidbg (Android ARM64 Emulator)
- Unicorn (CPU 模拟引擎)
- Capstone (反汇编)
- Keystone (汇编)

## 🎯 第一阶段：间接跳转反混淆
1. 识别 OLLVM 的间接跳转模式
2. 使用 unidbg 动态跟踪执行
3. 恢复原始控制流

## ✅ 开发进度
- [x] 项目框架建立
- [x] CLAUDE.md 建立
- [x] 移除硬编码入口点，添加灵活函数支持
- [ ] 间接跳转模式识别增强
- [ ] 测试框架
- [ ] 示例代码

## 🔑 关键决策

### 函数地址查找方式
- 使用 `module.findSymbolByName(name)` 查找符号
- 支持按符号名称 `-f <name>` 或偏移 `-x <offset>` 指定目标函数
- 符号查找失败时提供友好错误消息

### API 选择
- 使用 Unidbg 而非直接使用 Unicorn，简化 SO 加载和符号管理
- 使用 Keystone 生成 Patch 指令，确保机器码正确性

## 🔑 关键决策
- (在此记录重要技术决策和原因)

## 已知问题和解决方案
- (在此记录已知问题和如何解决)

## 📋 待实现功能
- 间接跳转
- 控制流平坦化还原
- 字符串加密还原
- 花指令还原
### IndirectJumpDeobfuscator 需要改进的点
1. 移除硬编码入口点 `0x10000`
2. 添加灵活的函数入口支持（通过命令行或配置）
3. 完善 SO 文件验证
4. 改进跳转目标解析逻辑
5. 添加更详细的日志和错误处理

