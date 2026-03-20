package com.ollvm.core;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;

import java.util.ArrayList;
import java.util.List;

/**
 * 环境管理器
 * 负责管理环境补充回调和缺失符号监听
 */
public class EnvironmentManager {

    /**
     * 环境补充接口
     * 用于在运行时补充缺失的 JNI 函数或系统调用
     */
    public interface EnvironmentPatcher {
        /**
         * 当模拟器需要补充环境时调用
         *
         * @param emulator 模拟器实例
         * @param module    目标模块
         * @param symbolName 缺失的符号名称（可为 null）
         * @return true 如果成功补充环境，false 如果无法补充
         */
        boolean patchEnvironment(AndroidEmulator emulator, Module module, String symbolName);
    }

    /**
     * 缺失符号监听接口
     * 当发现缺失符号时触发
     */
    public interface MissingSymbolListener {
        /**
         * 发现缺失符号时调用
         *
         * @param symbolName 符号名称
         * @param moduleName 模块名称
         */
        void onMissingSymbol(String symbolName, String moduleName);
    }

    private final List<EnvironmentPatcher> patchers = new ArrayList<>();
    private final List<MissingSymbolListener> listeners = new ArrayList<>();

    /**
     * 添加环境补充器
     */
    public void addPatcher(EnvironmentPatcher patcher) {
        if (patcher != null) {
            patchers.add(patcher);
        }
    }

    /**
     * 添加缺失符号监听器
     */
    public void addMissingSymbolListener(MissingSymbolListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    /**
     * 尝试补充环境
     * 依次调用所有已注册的环境补充器
     *
     * @param emulator 模拟器实例
     * @param module 目标模块
     * @param symbolName 缺失的符号名称
     * @return true 如果至少有一个补充器成功，false 否则
     */
    public boolean tryPatchEnvironment(AndroidEmulator emulator, Module module, String symbolName) {
        if (patchers.isEmpty()) {
            return false;
        }

        // 通知所有监听器
        for (MissingSymbolListener listener : listeners) {
            listener.onMissingSymbol(symbolName, module.name);
        }

        // 尝试所有补充器
        for (EnvironmentPatcher patcher : patchers) {
            try {
                if (patcher.patchEnvironment(emulator, module, symbolName)) {
                    return true;
                }
            } catch (Exception e) {
                // 忽略单个补充器的异常，继续尝试其他补充器
                e.printStackTrace();
            }
        }

        return false;
    }

    /**
     * 检查是否有注册的环境补充器
     */
    public boolean hasPatchers() {
        return !patchers.isEmpty();
    }

    /**
     * 获取环境补充器数量
     */
    public int getPatchersCount() {
        return patchers.size();
    }

    /**
     * 清除所有环境补充器和监听器
     */
    public void clear() {
        patchers.clear();
        listeners.clear();
    }
}
