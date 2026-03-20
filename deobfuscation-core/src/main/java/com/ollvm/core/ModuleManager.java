package com.ollvm.core;

import com.github.unidbg.Module;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 模块包装类
 * 包装 Module，包含加载时间等元数据
 */
class ModuleWrapper {
    final Module module;
    final DalvikModule dalvikModule;
    final String name;
    final long loadTime;
    boolean autoUnload;

    ModuleWrapper(Module module, DalvikModule dalvikModule, String name, boolean autoUnload) {
        this.module = module;
        this.dalvikModule = dalvikModule;
        this.name = name;
        this.loadTime = System.currentTimeMillis();
        this.autoUnload = autoUnload;
    }
}

/**
 * 模块管理器
 * 统一管理 SO 文件的加载和卸载
 */
public class ModuleManager {

    private final VM vm;
    private final Map<String, ModuleWrapper> loadedModules = new HashMap<>();
    private final List<ModuleWrapper> moduleList = new ArrayList<>();

    ModuleManager(VM vm) {
        this.vm = vm;
    }

    /**
     * 加载模块（从文件）
     *
     * @param file SO 文件
     * @param forceCallInit 是否强制调用初始化函数
     * @return 模块包装器
     */
    public ModuleWrapper loadModule(File file, boolean forceCallInit) {
        try {
            DalvikModule dm = vm.loadLibrary(file, forceCallInit);
            Module module = dm.getModule();

            String name = file.getName();
            ModuleWrapper wrapper = new ModuleWrapper(module, dm, name, true);

            loadedModules.put(name, wrapper);
            moduleList.add(wrapper);

            return wrapper;
        } catch (Exception e) {
            throw new RuntimeException("加载模块失败: " + file.getPath(), e);
        }
    }

    /**
     * 加载模块（从文件路径字符串）
     *
     * @param filePath SO 文件路径
     * @param forceCallInit 是否强制调用初始化函数
     * @return 模块包装器
     */
    public ModuleWrapper loadModule(String filePath, boolean forceCallInit) {
        return loadModule(new File(filePath), forceCallInit);
    }

    /**
     * 加载模块（按名称查找）
     *
     * @param libName 库名称（如 libc.so）
     * @param forceCallInit 是否强制调用初始化函数
     * @return 模块包装器
     */
    public ModuleWrapper loadModuleByName(String libName, boolean forceCallInit) {
        // 尝试从已加载的模块中查找
        ModuleWrapper existing = loadedModules.get(libName);
        if (existing != null) {
            return existing;
        }

        // 尝试加载系统库
        try {
            DalvikModule dm = vm.loadLibrary(libName, forceCallInit);
            Module module = dm.getModule();

            ModuleWrapper wrapper = new ModuleWrapper(module, dm, libName, false);

            loadedModules.put(libName, wrapper);
            moduleList.add(wrapper);

            return wrapper;
        } catch (Exception e) {
            throw new RuntimeException("加载模块失败: " + libName, e);
        }
    }

    /**
     * 获取已加载的模块
     *
     * @param name 模块名称
     * @return 模块包装器，如果不存在返回 null
     */
    public ModuleWrapper getModule(String name) {
        return loadedModules.get(name);
    }

    /**
     * 查找符号
     *
     * @param symbolName 符号名称
     * @return 符号值，如果不存在返回 null
     */
    public Long findSymbol(String symbolName) {
        for (ModuleWrapper wrapper : moduleList) {
            com.github.unidbg.Symbol symbol = wrapper.module.findSymbolByName(symbolName);
            if (symbol != null && !symbol.isUndef()) {
                return symbol.getValue();
            }
        }
        return null;
    }

    /**
     * 在指定模块中查找符号
     *
     * @param moduleName 模块名称
     * @param symbolName 符号名称
     * @return 符号值，如果不存在返回 null
     */
    public Long findSymbol(String moduleName, String symbolName) {
        ModuleWrapper wrapper = loadedModules.get(moduleName);
        if (wrapper != null) {
            com.github.unidbg.Symbol symbol = wrapper.module.findSymbolByName(symbolName);
            if (symbol != null && !symbol.isUndef()) {
                return symbol.getValue();
            }
        }
        return null;
    }

    /**
     * 卸载指定模块
     *
     * @param name 模块名称
     * @return true 如果成功卸载，false 如果模块不存在
     */
    public boolean unloadModule(String name) {
        ModuleWrapper wrapper = loadedModules.remove(name);
        if (wrapper != null) {
            moduleList.remove(wrapper);
            return true;
        }
        return false;
    }

    /**
     * 卸载所有自动卸载标记为 true 的模块
     */
    public void unloadAutoUnloadModules() {
        List<ModuleWrapper> toRemove = new ArrayList<>();

        for (ModuleWrapper wrapper : moduleList) {
            if (wrapper.autoUnload) {
                toRemove.add(wrapper);
            }
        }

        for (ModuleWrapper wrapper : toRemove) {
            loadedModules.remove(wrapper.name);
            moduleList.remove(wrapper);
        }
    }

    /**
     * 卸载所有模块
     */
    public void unloadAll() {
        loadedModules.clear();
        moduleList.clear();
    }

    /**
     * 获取已加载模块的数量
     */
    public int getLoadedCount() {
        return loadedModules.size();
    }

    /**
     * 获取已加载模块的名称列表
     */
    public List<String> getLoadedModuleNames() {
        return new ArrayList<>(loadedModules.keySet());
    }

    /**
     * 获取 VM 实例
     */
    public VM getVM() {
        return vm;
    }
}
