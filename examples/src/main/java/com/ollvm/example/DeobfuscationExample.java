package com.ollvm.example;

import com.ollvm.indirectjump.UnidbgIndirectJumpDeobfuscator;

/**
 * OLLVM 反混淆工具使用示例
 * 演示如何使用间接跳转反混淆器
 */
public class DeobfuscationExample {

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            return;
        }

        String inputPath = args[0];
        String outputPath = args.length > 1 ? args[1] : null;

        System.out.println("OLLVM 反混淆工具 - 使用示例");
        System.out.println("==============================");
        System.out.println("输入文件: " + inputPath);
        if (outputPath != null) {
            System.out.println("输出文件: " + outputPath);
        }
        System.out.println();

        try {
            UnidbgIndirectJumpDeobfuscator deobfuscator =
                outputPath != null ? new UnidbgIndirectJumpDeobfuscator(inputPath, outputPath)
                                   : new UnidbgIndirectJumpDeobfuscator(inputPath);

            // 配置参数
            deobfuscator.setVerbose(true)
                       .setSearchRange(0x10000, 0x200000);

            // 执行去混淆
            boolean success = deobfuscator.deobfuscate();

            System.out.println();
            System.out.println("反混淆结果: " + (success ? "成功" : "失败"));

        } catch (Exception e) {
            System.err.println("反混淆失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void printUsage() {
        System.out.println("OLLVM 反混淆工具 - 使用示例");
        System.out.println("==============================");
        System.out.println();
        System.out.println("用法:");
        System.out.println("  java DeobfuscationExample <input_so_file> [output_so_file]");
        System.out.println();
        System.out.println("示例:");
        System.out.println("  java DeobfuscationExample libobfuscated.so");
        System.out.println("  java DeobfuscationExample libobfuscated.so libdeobfuscated.so");
        System.out.println();
        System.out.println("说明:");
        System.out.println("  - 输入文件: 需要反混淆的 ARM64 SO 文件");
        System.out.println("  - 输出文件: 反混淆后的 SO 文件（可选，默认在原文件名后加 '_patch'）");
    }
}
