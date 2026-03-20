package com.ollvm.core;

import com.github.unidbg.arm.backend.BackendFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 模拟器配置类
 * 使用 Builder 模式构建模拟器配置
 */
public class EmulatorConfig {

    private boolean is64Bit = true;
    private String processName = "com.ollvm.deobfuscation";
    private File rootDir;
    private List<BackendFactory> backendFactories;
    private boolean verboseVM = false;
    private boolean autoCreateVM = true;

    private EmulatorConfig() {
        this.backendFactories = new ArrayList<>();
    }

    /**
     * 创建默认配置
     */
    public static EmulatorConfig create() {
        return new EmulatorConfig();
    }

    /**
     * 设置是否为 64 位模式
     */
    public EmulatorConfig set64Bit(boolean is64Bit) {
        this.is64Bit = is64Bit;
        return this;
    }

    /**
     * 设置进程名称
     */
    public EmulatorConfig setProcessName(String processName) {
        this.processName = processName;
        return this;
    }

    /**
     * 设置根目录
     */
    public EmulatorConfig setRootDir(File rootDir) {
        this.rootDir = rootDir;
        return this;
    }

    /**
     * 添加后端工厂
     */
    public EmulatorConfig addBackendFactory(BackendFactory factory) {
        this.backendFactories.add(factory);
        return this;
    }

    /**
     * 设置 VM 详细输出
     */
    public EmulatorConfig setVerboseVM(boolean verbose) {
        this.verboseVM = verbose;
        return this;
    }

    /**
     * 设置是否自动创建 VM
     */
    public EmulatorConfig disableAutoCreateVM() {
        this.autoCreateVM = false;
        return this;
    }

    /**
     * 启用自动创建 VM
     */
    public EmulatorConfig enableAutoCreateVM() {
        this.autoCreateVM = true;
        return this;
    }

    // Getter 方法
    public boolean is64Bit() {
        return is64Bit;
    }

    public String getProcessName() {
        return processName;
    }

    public File getRootDir() {
        return rootDir;
    }

    public List<BackendFactory> getBackendFactories() {
        return backendFactories;
    }

    public boolean isVerboseVM() {
        return verboseVM;
    }

    public boolean isAutoCreateVM() {
        return autoCreateVM;
    }
}
