package com.ollvm;

import com.ollvm.indirectjump.UnidbgIndirectJumpDeobfuscator;

/**
 * OLLVM 间接跳转反混淆工具主入口类
 */
public class Main {

    public static void main(String[] args) {
        System.out.println("OLLVM 间接跳转反混淆工具");
        System.out.println("======================");
        System.out.println();

        if (args.length == 0) {
            printUsage();
            return;
        }

        String command = args[0];

        try {
            switch (command) {
                case "indirect-jump":
                    handleIndirectJump(args);
                    break;
                default:
                    System.out.println("未知命令: " + command);
                    printUsage();
            }
        } catch (Exception e) {
            System.err.println("执行失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void handleIndirectJump(String[] args) {
        if (args.length < 2) {
            System.out.println("用法: indirect-jump <so_file_path> [output_path]");
            return;
        }

        String inputPath = args[1];
        String outputPath = args.length > 2 ? args[2] : null;

        UnidbgIndirectJumpDeobfuscator deobfuscator =
            outputPath != null ? new UnidbgIndirectJumpDeobfuscator(inputPath, outputPath)
                               : new UnidbgIndirectJumpDeobfuscator(inputPath);

        deobfuscator.setVerbose(true)
                   .setSearchRange(0x10000, 0x200000);

        boolean success = deobfuscator.deobfuscate();
        System.out.println("\n间接跳转反混淆: " + (success ? "成功" : "失败"));
    }

    private static void printUsage() {
        System.out.println("用法:");
        System.out.println("  java -jar ollvm-deobfuscation-1.0.0-jar-with-dependencies.jar <命令> <参数>");
        System.out.println("");
        System.out.println("命令列表:");
        System.out.println("  indirect-jump  <so文件> [输出文件]  - 处理间接跳转混淆");
        System.out.println("");
        System.out.println("示例:");
        System.out.println("  java -jar ollvm-deobfuscation-1.0.0-jar-with-dependencies.jar indirect-jump libobfuscated.so");
    }
}
