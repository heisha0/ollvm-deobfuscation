package com.ollvm.core;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.arm.backend.BackendFactory;

import java.io.IOException;
import java.util.List;

/**
 * 模拟器管理器
 * 核心模拟器生命周期管理，支持 AutoCloseable
 */
public class EmulatorManager implements AutoCloseable {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final EnvironmentManager environmentManager;
    private final ModuleManager moduleManager;
    private final boolean ownsResources;
    private boolean closed = false;

    /**
     * 私有构造函数
     */
    private EmulatorManager(AndroidEmulator emulator, VM vm,
                          EnvironmentManager environmentManager,
                          ModuleManager moduleManager,
                          boolean ownsResources) {
        this.emulator = emulator;
        this.vm = vm;
        this.environmentManager = environmentManager;
        this.moduleManager = moduleManager;
        this.ownsResources = ownsResources;
    }

    /**
     * 创建模拟器管理器（使用指定配置）
     *
     * @param config 模拟器配置
     * @return 模拟器管理器
     */
    public static EmulatorManager create(EmulatorConfig config) {
        if (config == null) {
            config = EmulatorConfig.create();
        }

        // 创建模拟器
        AndroidEmulator emulator;
        if (config.is64Bit()) {
            com.github.unidbg.EmulatorBuilder<AndroidEmulator> builder = AndroidEmulatorBuilder.for64Bit()
                    .setProcessName(config.getProcessName());
            if (config.getRootDir() != null) {
                builder.setRootDir(config.getRootDir());
            }
            List<BackendFactory> factories = config.getBackendFactories();
            for (int i = 0; i < factories.size(); i++) {
                builder.addBackendFactory(factories.get(i));
            }
            emulator = builder.build();
        } else {
            com.github.unidbg.EmulatorBuilder<AndroidEmulator> builder = AndroidEmulatorBuilder.for32Bit()
                    .setProcessName(config.getProcessName());
            if (config.getRootDir() != null) {
                builder.setRootDir(config.getRootDir());
            }
            List<BackendFactory> factories = config.getBackendFactories();
            for (int i = 0; i < factories.size(); i++) {
                builder.addBackendFactory(factories.get(i));
            }
            emulator = builder.build();
        }

        // 设置库解析器
        emulator.getMemory().setLibraryResolver(new AndroidResolver(28));

        // 创建 VM
        VM vm = null;
        if (config.isAutoCreateVM()) {
            vm = emulator.createDalvikVM();
            vm.setVerbose(config.isVerboseVM());
        }

        // 创建管理器
        EnvironmentManager envManager = new EnvironmentManager();
        ModuleManager modManager = (vm != null) ? new ModuleManager(vm) : null;

        return new EmulatorManager(emulator, vm, envManager, modManager, true);
    }

    /**
     * 创建默认的 64 位模拟器管理器
     *
     * @return 模拟器管理器
     */
    public static EmulatorManager createDefault64Bit() {
        return create(EmulatorConfig.create().set64Bit(true));
    }

    /**
     * 创建默认的 32 位模拟器管理器
     *
     * @return 模拟器管理器
     */
    public static EmulatorManager createDefault32Bit() {
        return create(EmulatorConfig.create().set64Bit(false));
    }

    /**
     * 共享资源模式创建（不关闭传入的资源）
     *
     * @param emulator 已存在的模拟器实例
     * @param vm 已存在的 VM 实例
     * @param config 配置（可选）
     * @return 模拟器管理器
     */
    public static EmulatorManager createShared(AndroidEmulator emulator, VM vm, EmulatorConfig config) {
        EnvironmentManager envManager = new EnvironmentManager();
        ModuleManager modManager = (vm != null) ? new ModuleManager(vm) : null;
        return new EmulatorManager(emulator, vm, envManager, modManager, false);
    }

    /**
     * 共享资源模式创建（使用默认配置）
     *
     * @param emulator 已存在的模拟器实例
     * @param vm 已存在的 VM 实例
     * @return 模拟器管理器
     */
    public static EmulatorManager createShared(AndroidEmulator emulator, VM vm) {
        return createShared(emulator, vm, null);
    }

    /**
     * 启动模拟器
     */
    public void start() {
        if (closed) {
            throw new IllegalStateException("模拟器已关闭");
        }
        // 目前没有特殊启动逻辑，模拟器在构造时已就绪
    }

    /**
     * 停止模拟器（不关闭资源）
     */
    public void stop() {
        if (closed) {
            return;
        }
        // 停止模拟器但不关闭资源
        if (emulator != null) {
            try {
                emulator.attach();
            } catch (Exception e) {
                // 忽略
            }
        }
    }

    /**
     * 关闭模拟器并释放所有资源
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        closed = true;

        // 卸载所有模块
        if (moduleManager != null) {
            moduleManager.unloadAll();
        }

        // 关闭模拟器（仅当拥有资源时）
        if (ownsResources && emulator != null) {
            try {
                emulator.close();
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("关闭模拟器失败", e);
            }
        }
    }

    /**
     * 检查是否已关闭
     */
    public boolean isClosed() {
        return closed;
    }

    /**
     * 获取模拟器实例
     */
    public AndroidEmulator getEmulator() {
        checkNotClosed();
        return emulator;
    }

    /**
     * 获取 VM 实例
     */
    public VM getVM() {
        checkNotClosed();
        return vm;
    }

    /**
     * 获取环境管理器
     */
    public EnvironmentManager getEnvironmentManager() {
        checkNotClosed();
        return environmentManager;
    }

    /**
     * 获取模块管理器
     */
    public ModuleManager getModuleManager() {
        checkNotClosed();
        return moduleManager;
    }

    /**
     * 检查是否拥有资源所有权
     */
    public boolean ownsResources() {
        return ownsResources;
    }

    /**
     * 检查是否未关闭
     */
    private void checkNotClosed() {
        if (closed) {
            throw new IllegalStateException("模拟器已关闭，无法访问资源");
        }
    }

    /**
     * 简化使用示例
     *
     * <pre>{@code
     * try (EmulatorManager manager = EmulatorManager.createDefault64Bit()) {
     *     // 加载模块
     *     ModuleManager moduleManager = manager.getModuleManager();
     *     ModuleWrapper wrapper = moduleManager.loadModule(new File("lib.so"), false);
     *
     *     // 使用模块
     *     Module module = wrapper.module;
     *
     * } // 自动关闭模拟器
     * }</pre>
     */
}
