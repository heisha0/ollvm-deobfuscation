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
            System.out.println("用法: indirect-jump <so_file_path> [选项]");
            System.out.println();
            System.out.println("选项:");
            System.out.println("  -o <output_path>     指定输出文件路径");
            System.out.println("  -f <function_name>    按符号名称指定目标函数");
            System.out.println("  -x <offset>           按偏移指定目标函数（十六进制）");
            System.out.println("  -r <start>-<end>      设置搜索范围（十六进制偏移）");
            System.out.println("  -v                    启用详细输出");
            System.out.println();
            System.out.println("示例:");
            System.out.println("  indirect-jump libobfuscated.so -f target_function");
            System.out.println("  indirect-jump libobfuscated.so -x 0x10000 -o lib_patched.so");
            return;
        }

        String inputPath = args[1];
        String outputPath = null;
        String functionName = null;
        Long functionOffset = null;
        int searchStart = 0;
        int searchEnd = Integer.MAX_VALUE;
        boolean verbose = true;

        // 解析参数
        for (int i = 2; i < args.length; i++) {
            if (args[i].equals("-o") && i + 1 < args.length) {
                outputPath = args[++i];
            } else if (args[i].equals("-f") && i + 1 < args.length) {
                functionName = args[++i];
            } else if (args[i].equals("-x") && i + 1 < args.length) {
                functionOffset = Long.parseLong(args[++i].replace("0x", ""), 16);
            } else if (args[i].equals("-r") && i + 1 < args.length) {
                String range = args[++i];
                String[] parts = range.split("-");
                if (parts.length == 2) {
                    searchStart = Integer.parseInt(parts[0].replace("0x", ""), 16);
                    searchEnd = Integer.parseInt(parts[1].replace("0x", ""), 16);
                }
            } else if (args[i].equals("-v")) {
                verbose = true;
            } else if (args[i].equals("-q")) {
                verbose = false;
            }
        }

        UnidbgIndirectJumpDeobfuscator deobfuscator =
            outputPath != null ? new UnidbgIndirectJumpDeobfuscator(inputPath, outputPath)
                               : new UnidbgIndirectJumpDeobfuscator(inputPath);

        // 配置参数
        deobfuscator.setVerbose(verbose)
                   .setSearchRange(searchStart, searchEnd);

        if (functionName != null) {
            deobfuscator.setFunctionName(functionName);
        }
        if (functionOffset != null) {
            deobfuscator.setFunctionOffset(functionOffset);
        }

        boolean success = deobfuscator.deobfuscate();
        System.out.println("\n间接跳转反混淆: " + (success ? "成功" : "失败"));
        if (success) {
            System.out.println("输出文件: " + outputPath);
        }
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
