# OLLVM 反混淆工具库

这个目录包含用于对抗 OLLVM（Obfuscator-LLVM）混淆的完整工具集合。

## 目录结构

```
ollvm-deobfuscation/
├── README.md                    # 本文件 - 使用说明
├── src/main/java/com/ollvm/
│   ├── indirectjump/            # 间接跳转反混淆
│   │   └── UnidbgIndirectJumpDeobfuscator.java
│   ├── stringencryption/        # 字符串加密反混淆
│   │   └── UnidbgStringDecryptor.java
│   └── utils/                   # 工具类
│       └── XorDecryptor.java
├── src/main/scripts/ida/
│   └── ollvm_analysis.py
└── pom.xml
```

## 功能概述

### 1. 间接跳转反混淆
使用 Unidbg 动态执行和指令级跟踪，识别并去除 OLLVM 的间接跳转混淆。

**特点：**
- 动态指令跟踪和栈回溯
- 自动识别 `csel` → `ldr` → `br` 模式
- 计算跳转目标地址
- 自动生成 Patch 指令
- 输出修复后的 SO 文件

### 2. 字符串加密反混淆
使用 Unidbg 动态执行，识别解密函数并恢复加密字符串。

**特点：**
- 自动识别解密函数
- 动态钩子解密过程
- 恢复加密字符串
- 生成解密报告

### 3. IDA Pro 辅助脚本
在 IDA Pro 中使用的 Python 脚本，帮助静态分析和定位混淆模式。

**特点：**
- 查找间接跳转
- 识别解密函数候选
- 查找地址表
- 自动命名和着色
- 导出分析报告

### 4. 通用工具
包含 XOR 解密等通用工具，适用于简单的字符串解密场景。

## 前置条件

### 系统要求
- Java 8 或更高版本
- Android SDK（用于 Unidbg）
- IDA Pro 7.0 或更高版本（用于 Python 脚本）

### 依赖库
- Unidbg - 动态分析框架
- Capstone - 反汇编引擎
- Keystone - 汇编引擎
- Unicorn - CPU 模拟器

## 快速开始

### 使用间接跳转反混淆器

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

### 使用字符串解密器

```java
import com.ollvm.stringencryption.UnidbgStringDecryptor;
import com.ollvm.stringencryption.UnidbgStringDecryptor.DecryptedString;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        // 创建解密器
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

### 在 IDA Pro 中使用

1. 打开 IDA Pro 并加载混淆的二进制文件
2. 运行脚本：`File -> Script file... -> 选择 ollvm_analysis.py`
3. 选择菜单选项进行分析

```python
# 手动运行特定功能
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
```

## 详细使用指南

### 间接跳转反混淆使用步骤

#### 1. 准备工作
```bash
# 确保有混淆的 SO 文件
ls -la libobfuscated.so
```

#### 2. 配置 Unidbg 环境
在项目的 pom.xml 中已包含依赖。

#### 3. 运行反混淆
```bash
# 编译并运行
cd ollvm-deobfuscation
mvn clean package
java -jar target/ollvm-deobfuscation-1.0.0-jar-with-dependencies.jar indirect-jump libobfuscated.so
```

#### 4. 验证结果
```bash
# 检查输出文件
ls -la libobfuscated_patch.so

# 使用 IDA Pro 重新加载并反编译
```

### 字符串加密反混淆使用步骤

#### 1. 识别解密函数
先在 IDA Pro 中打开文件，使用 ollvm_analysis.py 查找解密函数。

#### 2. 配置分析范围
```java
// 如果知道解密函数的地址，可以直接指定
deobfuscator.setSearchRange(decryptFuncAddr, decryptFuncAddr + 0x100);
```

#### 3. 运行解密并检查报告
```bash
# 解密报告会自动生成
cat libobfuscated_decrypted.txt
```

## 工具类说明

### XorDecryptor
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

## 常见问题

### Q: 如何构建和配置 Unidbg 环境？
A: 参考 Unidbg 官方文档：https://github.com/zhkl0228/unidbg

### Q: 反混淆后程序无法运行怎么办？
A:
1. 检查分析范围是否正确
2. 尝试调整搜索范围
3. 检查是否还有其他混淆技术
4. 使用更保守的 Patch 策略

### Q: IDA Pro 脚本不起作用？
A:
1. 确保 IDA Pro 版本支持 Python 3
2. 检查脚本路径是否正确
3. 先运行 `idc.auto_wait()` 完成自动分析

### Q: 字符串解密器找不到字符串？
A:
1. 确保运行了初始化函数
2. 尝试手动触发解密
3. 检查密钥是否正确提取

## 混淆模式识别

### 间接跳转模式
```arm64
add  x21, x21, #0xd0         ; 基地址计算
csel w8, w8, w10, eq         ; 条件选择索引
ldr  x8, [x21, w8, uxtw #3]  ; 从数组加载地址
br   x8                      ; 间接跳转
```

### 字符串加密模式
```c
void decrypt_string(char *out, const char *in) {
    for (int i = 0; i < len; i++) {
        out[i] = in[i] ^ key[i % key_len];
    }
}
```

## 扩展开发

### 添加新的反混淆技术

1. 在对应目录下创建新类
2. 实现相应的接口
3. 添加到主流程中

```java
// 示例：添加新的解密技术
public class NewDeobfuscationTechnique {
    public boolean process(Module module) {
        // 实现你的反混淆逻辑
        return true;
    }
}
```

## 注意事项

1. **法律合规**：仅用于授权的安全研究和学习
2. **备份原始文件**：处理前务必备份
3. **测试环境**：建议在虚拟机或测试环境中使用
4. **伦理使用**：不要用于未授权的逆向工程

## 参考资料

- [OLLVM 官方文档](https://github.com/obfuscator-llvm/obfuscator)
- [Unidbg 项目](https://github.com/zhkl0228/unidbg)
- [Capstone 反汇编](https://www.capstone-engine.org/)
- [Keystone 汇编](https://www.keystone-engine.org/)

## 许可证

仅供学习和安全研究使用。

---

## 贡献

欢迎提交问题和改进建议！