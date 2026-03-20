# OLLVM 反混淆工具库

一个用于对抗 OLLVM (Obfuscator-LLVM) 混淆的完整工具集，主要针对 ARM64 Android 共享库 (.so 文件)。

## 项目简介

本项目采用模块化 Maven 架构，提供多种反混淆技术来对抗 OLLVM 的各种混淆方式，包括间接跳转混淆、字符串加密等。

### 核心功能

- **间接跳转反混淆**：使用 Unidbg 动态执行和指令级跟踪，识别并去除 OLLVM 的间接跳转混淆
- **字符串加密反混淆**：自动识别解密函数并恢复加密字符串
- **IDA Pro 辅助脚本**：提供静态分析工具，帮助定位混淆模式
- **通用工具**：包含 XOR 解密等通用工具

## 项目架构

```
ollvm-deobfuscation/
├── deobfuscation-core/          # 核心反混淆库
│   ├── src/main/java/com/ollvm/
│   │   ├── indirectjump/        # 间接跳转反混淆
│   │   ├── stringencryption/    # 字符串加密反混淆
│   │   └── utils/               # 工具类
│   └── pom.xml
├── unidbg-wrapper/              # Unidbg 模拟器框架封装
│   ├── src/main/java/com/github/unidbg/
│   │   ├── arm/                 # ARM64 模拟器
│   │   ├── backend/             # 后端实现
│   │   └── debugger/            # 调试器支持
│   └── pom.xml
├── examples/                    # 使用示例代码
│   └── pom.xml
├── test/                        # 单元测试和集成测试
│   └── pom.xml
├── src/main/
│   ├── java/com/ollvm/          # 主入口
│   └── scripts/ida/             # IDA Pro 辅助脚本
│       └── ollvm_analysis.py
├── pom.xml                      # Maven 父 POM
└── README.md
```

### 模块说明

| 模块 | 说明 | 依赖 |
|------|------|------|
| **deobfuscation-core** | 核心反混淆功能库，包含间接跳转反混淆、字符串解密等 | unidbg-wrapper |
| **unidbg-wrapper** | 精简版 Unidbg 框架，仅包含 ARM64 Android 模拟器支持 | Unicorn, Capstone, Keystone |
| **examples** | 使用示例代码，展示如何使用反混淆功能 | deobfuscation-core, unidbg-wrapper |
| **test** | 单元测试和集成测试 | deobfuscation-core |

## 环境要求

- **Java**：JDK 8 或更高版本
- **Maven**：3.6 或更高版本
- **Android SDK**：用于 Unidbg（可选，如需模拟完整 Android 环境）
- **IDA Pro**：7.0 或更高版本（用于使用 Python 脚本，可选）

### 依赖库

| 库 | 版本 | 用途 |
|----|------|------|
| Unicorn | 1.0.14 | CPU 模拟器引擎 |
| Capstone | 3.1.8 | 反汇编引擎 |
| Keystone | 0.9.7 | 汇编引擎 |
| FastJSON | 1.2.83 | JSON 处理 |
| Apache Commons | - | 通用工具类 |
| SLF4J | 1.7.36 | 日志框架 |

## 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/your-username/ollvm-deobfuscation.git
cd ollvm-deobfuscation

# 编译项目
mvn clean install

# 编译特定模块
mvn clean install -pl deobfuscation-core
```

### 命令行使用

```bash
# 编译并打包
mvn clean package

# 运行间接跳转反混淆
java -cp deobfuscation-core/target/deobfuscation-core-1.0.0-jar-with-dependencies.jar \
     com.ollvm.Main indirect-jump libobfuscated.so

# 运行字符串解密
java -cp deobfuscation-core/target/deobfuscation-core-1.0.0-jar-with-dependencies.jar \
     com.ollvm.Main string-decrypt libobfuscated.so
```

### Java API 使用

#### 间接跳转反混淆

```java
import com.ollvm.indirectjump.UnidbgIndirectJumpDeobfuscator;

public class Main {
    public static void main(String[] args) {
        // 创建反混淆器
        UnidbgIndirectJumpDeobfuscator deobfuscator =
            new UnidbgIndirectJumpDeobfuscator("libobfuscated.so");

        // 配置参数
        deobfuscator.setVerbose(true)
                   .setSearchRange(0x10000, 0x200000);

        // 执行去混淆
        boolean success = deobfuscator.deobfuscate();

        if (success) {
            System.out.println("去混淆成功！");
        }
    }
}
```

#### 字符串解密

```java
import com.ollvm.stringencryption.UnidbgStringDecryptor;
import com.ollvm.stringencryption.UnidbgStringDecryptor.DecryptedString;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        // 创建创建解密器
        UnidbgStringDecryptor decryptor =
            new UnidbgStringDecryptor("libobfuscated.so");

        // 配置并运行
        decryptor.setVerbose(true);
        boolean success = decryptor.decrypt();

        if (success) {
            // 获取解密结果
            List<DecryptedString> strings = decryptor.getDecryptedStrings();

            for (DecryptedString s : strings) {
                System.out.printf("0x%x: %s\n", s.address, s.value);
            }
        }
    }
}
```

### IDA Pro 使用

1. 打开 IDA Pro 并加载混淆的二进制文件
2. 运行脚本：`File -> Script file... -> 选择 ollvm_analysis.py`
3. 选择菜单选项进行分析

```python
# 在 IDA Pro Python 控制台中
import ollvm_analysis as ollvm

# 设置调试模式
ollvm.set_debug(True)

# 分析间接跳转
jumps = ollvm.analyze_indirect_jumps()

# 分析字符串加密
strings, candidates = ollvm.analyze_string_encryption()

# 导出完整报告
report = ollvm.export_analysis()
ollvm.save_report(report, "analysis.json")

# 自动命名混淆函数
ollvm.auto_naming()
```

## 详细功能说明

### 1. 间接跳转反混淆

OLLVM 使用间接跳转混淆来破坏控制流，该功能通过动态执行和指令跟踪来恢复原始控制流。

**特点：**
- 动态指令跟踪和栈回溯
- 自动识别 `csel` → `ldr` → `br` 模式
- 计算跳转目标地址
- 自动生成 Patch 指令
- 输出修复后的 SO 文件

**混淆模式示例：**
```arm64
add  x21, x21, #0xd0         ; 基地址计算
csel w8, w8, w10, eq         ; 条件选择索引
ldr  x8, [x21, w8, uxtw #3]  ; 从数组加载地址
br   x8                      ; 间接跳转
```

### 2. 字符串加密反混淆

识别 OLLVM 的字符串加密函数，通过动态钩子捕获解密过程。

**特点：**
- 自动识别解密函数
- 动态钩子解密过程
- 恢复加密字符串
- 生成解密报告

### 3. IDA Pro 辅助脚本

提供静态分析工具，帮助在 IDA Pro 中定位和分析混淆模式。

**功能：**
- 查找间接跳转
- 识别解密函数候选
- 查找地址表
- 自动命名和着色
- 导出分析报告

### 4. XOR 工具

通用的 XOR 解密工具，适用于简单的字符串解密场景。

```java
import com.ollvm.utils.XorDecryptor;

// 使用已知密钥解密
byte[] key = new byte[] { 0x55, (byte) 0xaa, 0x55, (byte) 0xaa };
byte[] decrypted = XorDecryptor.xorDecrypt(encryptedData, key);

// 尝试多个密钥
List<byte[]> keys = Arrays.asList(
    XorDecryptor.XOR_KEY_0,
    XorDecryptor.XOR_KEY_55AA,
    XorDecryptor.XOR_KEY_AA55
);
XorDecryptor.DecryptionResult result = XorDecryptor.tryMultipleKeys(data, keys);

// 自动检测密钥（暴力破解）
byte[] autoKey = XorDecryptor.autoDetectKey(data, 8);
```

## 运行测试

```bash
# 运行所有测试
mvn test

# 运行特定模块的测试
mvn test -pl deob
fuscation-core

# 运行测试并生成报告
mvn test -pl test
```

## 常见问题

### Q: 如何构建和配置 Unidbg 环境？

A: 本项目已包含精简版 Unidbg 封装（unidbg-wrapper），无需额外配置。如需使用完整 Unidbg，参考 [Unidbg 官方文档](https://github.com/zhkl0228/unidbg)。


## 开发指南

### 添加新的反混淆技术

1. 在 `deobfuscation-core/src/main/java/com/ollvm/` 下创建新包
2. 实现相应的反混淆类
3. 在 `examples` 模块中添加使用示例
4. 在 `test` 模块中添加单元测试

```java
// 示例：添加新的解密技术
package com.ollvm.newtechnique;

public class NewDeobfuscationTechnique {
    public boolean process(Module module) {
        // 实现你的反混淆逻辑
        return true;
    }
}
```

### 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 提交 Pull Request

## 法律声明

本项目仅供学习和安全研究使用，请遵守以下原则：

- **法律合规**：仅用于授权的安全研究和学习
- **备份原始文件**：处理前务必备份
- **测试环境**：建议在虚拟机或测试环境中使用
- **伦理使用**：不要用于未授权的逆向工程

## 许可证

本项目采用 Apache License 2.0 许可证。详见 [LICENSE](LICENSE) 文件。

```
Copyright 2024 OLLVM Deobfuscation Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## 参考资料

- [OLLVM 官方文档](https://github.com/obfuscator-llvm/obfuscator)
- [Unidbg 项目](https://github.com/zhkl0228/unidbg)
- [Capstone 反汇编引擎](https://www.capstone-engine.org/)
- [Keystone 汇编引擎](https://www.keystone-engine.org/)

## 联系方式

- 提交问题：
- 讨论交流：
