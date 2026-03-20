package com.ollvm.examples;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.Module;
import com.ollvm.core.EmulatorManager;
import com.ollvm.core.EmulatorConfig;
import com.ollvm.core.EnvironmentManager;
import com.ollvm.indirectjump.UnidbgIndirectJumpDeobfuscator;

import java.io.File;

/**
 * 模拟器复用示例
 *
 * 展示如何使用 EmulatorManager 进行资源统一管理
 */
public class EmulatorReuseExample {

    public static void main(String[] args) {
        String soPath = "libobfuscated.so";

        if (args.length > 0) {
            soPath = args[0];
        }

        try {
            // ========== 方式 1：使用 EmulatorManager（推荐）==========
            System.out.println("=== 方式 1：使用 EmulatorManager ===");

            try (EmulatorManager manager = EmulatorManager.createDefault64Bit()) {
                // 1. 加载 SO 文件
                var moduleManager = manager.getModuleManager();
                var wrapper = moduleManager.loadModule(new File(soPath), false);
                Module module = wrapper.module;

                // 2. 添加环境补充器
                EnvironmentManager envManager = manager.getEnvironmentManager();
                envManager.addPatcher((emulator, mod, symbolName) -> {
                    System.out.println("[环境补充] 缺失符号: " + symbolName);
                    return patchMissingFunction(emulator, mod, symbolName);
                });

                // 3. 添加缺失符号监听器
                envManager.addMissingSymbolListener((symbolName, moduleName) -> {
                    System.out.println("[缺失符号] " + symbolName + " 在模块 " + moduleName);
                });

                // 4. 处理多个函数（使用同一个模拟器）
                String[] functions = {"function1", "function2", "check_integrity"};

                for (String funcName : functions) {
                    System.out.println("\n处理函数: " + funcName);

                    UnidbgIndirectJumpDeobfuscator deobfuscator =
                            new UnidbgIndirectJumpDeobfuscator(
                                    manager, soPath,
                                    funcName + "_patched.so");

                    deobfuscator.setModule(module)
                               .setFunctionName(funcName)
                               .setVerbose(true);

                    boolean success = deobfuscator.deobfuscate();
                    System.out.println("结果: " + (success ? "成功" : "失败"));
                }
            } // 自动关闭模拟器

            // ========== 方式 2：自定义配置 ==========
            System.out.println("\n=== 方式 2：自定义配置 ===");

            try (EmulatorManager manager = EmulatorManager.create(
                    EmulatorConfig.create()
                        .set64Bit(true)
                        .setProcessName("com.example.app")
                        .setVerboseVM(false))) {

                var moduleManager = manager.getModuleManager();
                var wrapper = moduleManager.loadModule(new File(soPath), false);
                Module module = wrapper.module;

                UnidbgIndirectJumpDeobfuscator deobfuscator =
                        new UnidbgIndirectJumpDeobfuscator(
                                manager, soPath,
                                "custom_patched.so");

                deobfuscator.setModule(module)
                           .setFunctionName("target_function")
                           .setVerbose(true);

                deobfuscator.deobfuscate();
            }

            // ========== 方式 3：共享已有模拟器 ==========
            System.out.println("\n=== 方式 3：共享已有模拟器 ===");

            // 外部创建模拟器（不推荐，但为了兼容性）
            var legacyEmulatorBuilder = com.github.unidbg.linux.android.AndroidEmulatorBuilder.for64Bit()
                    .setProcessName("com.example.app");
            AndroidEmulator externalEmulator = legacyEmulatorBuilder.build();
            externalEmulator.getMemory().setLibraryResolver(
                    new com.github.unidbg.linux.android.AndroidResolver(28));
            VM externalVm = externalEmulator.createDalvikVM();

            // 加载模块
            var dm = externalVm.loadLibrary(new File(soPath), false);
            Module externalModule = dm.getModule();

            // 创建共享的 EmulatorManager
            try (EmulatorManager manager = EmulatorManager.createShared(
                    externalEmulator, externalVm)) {

                // 添加环境补充器
                manager.getEnvironmentManager().addPatcher((em, mod, symbolName) -> {
                    return patchMissingFunction(em, mod, symbolName);
                });

                UnidbgIndirectJumpDeobfuscator deobfuscator =
                        new UnidbgIndirectJumpDeobfuscator(
                                manager, soPath,
                                "shared_patched.so");

                deobfuscator.setModule(externalModule)
                           .setFunctionName("another_function")
                           .setVerbose(true);

                deobfuscator.deobfuscate();
            }

            // 注意：外部创建的模拟器需要手动关闭
            externalEmulator.close();

            // ========== 方式 4：传统的每次创建（不推荐）==========
            System.out.println("\n=== 方式 4：传统方式（不推荐，易被检测）===");

            UnidbgIndirectJumpDeobfuscator deobf4 =
                    new UnidbgIndirectJumpDeobfuscator(soPath, "old_way_patched.so");

            deobf4.setFunctionName("some_function");
            deobf4.deobfuscate();
            // 这里会自动关闭模拟器

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 补充缺失的 JNI 函数
     */
    private static boolean patchMissingFunction(AndroidEmulator emulator,
                                            Module module,
                                            String symbolName) {
        switch (symbolName) {
            case "strlen":
                System.out.println("[环境补充] 已补充 strlen");
                // vm.addJniMethod(module, "strlen", true, new ...);
                return true;

            case "strcmp":
                System.out.println("[环境补充] 已补充 strcmp");
                // vm.addJniMethod(module, "strcmp", true, new ...);
                return true;

            case "some_custom_function":
                // 补充自定义函数
                return true;

            default:
                System.out.println("[环境补充] 无法补充: " + symbolName);
                return false;
        }
    }
}
