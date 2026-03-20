package com.ollvm.indirectjump;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.ollvm.core.EmulatorManager;
import com.ollvm.core.EnvironmentManager;
import capstone.Capstone;
import capstone.api.Instruction;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.Arm64Const;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Stack;

/**
 * OLLVM 间接跳转反混淆器 - Unidbg 实现
 * 用于处理 ARM64 架构下的间接跳转混淆
 */
public class UnidbgIndirectJumpDeobfuscator {

    private static final String DEFAULT_OUTPUT_SUFFIX = "_patch";

    private final AndroidEmulator emulator;
    private Module module;  // 使用 EmulatorManager 时延迟设置
    private final String inputPath;
    private final String outputPath;

    // 指令跟踪和分析相关
    private Stack<InstructionInfo> instructionStack;
    private List<PatchInfo> patchList;

    // 配置选项
    private boolean verbose = true;
    private int searchRangeStart = 0;
    private int searchRangeEnd = Integer.MAX_VALUE;
    private String functionName = null;  // 按名称查找函数
    private long functionOffset = -1;     // 按偏移调用函数

    // 环境管理
    private boolean ownsEmulator = false;  // 是否拥有模拟器的所有权
    private EmulatorManager emulatorManager;  // 模拟器管理器（可选）
    private EnvironmentPatcher legacyEnvironmentPatcher;  // 兼容旧版本的环境补充回调

    /**
     * 环境补充接口（旧版本，用于向后兼容）
     * 已废弃，请使用 EnvironmentManager
     */
    @Deprecated
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
     * 构造函数
     *
     * @param inputPath 输入的 SO 文件路径
     */
    public UnidbgIndirectJumpDeobfuscator(String inputPath) {
        this(inputPath, generateOutputPath(inputPath));
    }

    /**
     * 构造函数
     *
     * @param inputPath  输入的 SO 文件路径
     * @param outputPath 输出的 SO 文件路径
     */
    public UnidbgIndirectJumpDeobfuscator(String inputPath, String outputPath) {
        this.inputPath = inputPath;
        this.outputPath = outputPath;
        this.ownsEmulator = true;

        // 创建模拟器
        this.emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.ollvm.deobfuscation")
                .build();

        // 初始化内存和模块
        try {
            Memory memory = this.emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(28));

            VM vm = this.emulator.createDalvikVM();
            vm.setVerbose(false);

            // 加载模块
            File libFile = new File(inputPath);
            DalvikModule dm = vm.loadLibrary(libFile, false);
            this.module = dm.getModule();

            // 初始化分析组件
            this.instructionStack = new Stack<>();
            this.patchList = new ArrayList<>();

        } catch (Exception e) {
            throw new RuntimeException("初始化失败: " + e.getMessage(), e);
        }
    }

    /**
     * 构造函数 - 使用外部模拟器（推荐用于避免检测）
     *
     * @param emulator 已配置的模拟器实例（不关闭）
     * @param module    已加载的模块
     * @param inputPath  输入的 SO 文件路径（用于 Patch）
     * @param outputPath 输出的 SO 文件路径
     */
    public UnidbgIndirectJumpDeobfuscator(AndroidEmulator emulator, Module module,
                                         String inputPath, String outputPath) {
        this.inputPath = inputPath;
        this.outputPath = outputPath;
        this.emulator = emulator;
        this.module = module;
        this.ownsEmulator = false;  // 不关闭外部传入的模拟器

        // 初始化分析组件
        this.instructionStack = new Stack<>();
        this.patchList = new ArrayList<>();
    }

    /**
     * 构造函数 - 使用 EmulatorManager（推荐）
     *
     * @param manager 模拟器管理器
     * @param inputPath 输入的 SO 文件路径（用于 Patch）
     * @param outputPath 输出的 SO 文件路径
     */
    public UnidbgIndirectJumpDeobfuscator(EmulatorManager manager,
                                         String inputPath, String outputPath) {
        if (manager == null) {
            throw new IllegalArgumentException("EmulatorManager 不能为 null");
        }
        if (manager.isClosed()) {
            throw new IllegalStateException("EmulatorManager 已关闭");
        }

        this.emulatorManager = manager;
        this.emulator = manager.getEmulator();
        this.inputPath = inputPath;
        this.outputPath = outputPath;
        this.ownsEmulator = false;  // 由 EmulatorManager 管理生命周期

        // 初始化分析组件
        this.instructionStack = new Stack<>();
        this.patchList = new ArrayList<>();
    }

    /**
     * 设置目标模块（使用 EmulatorManager 时需要调用）
     *
     * @param module 目标模块
     * @return this
     */
    public UnidbgIndirectJumpDeobfuscator setModule(Module module) {
        this.module = module;
        return this;
    }

    /**
     * 设置详细输出模式
     */
    public UnidbgIndirectJumpDeobfuscator setVerbose(boolean verbose) {
        this.verbose = verbose;
        return this;
    }

    /**
     * 设置搜索范围（相对于模块基地址的偏移）
     */
    public UnidbgIndirectJumpDeobfuscator setSearchRange(int start, int end) {
        this.searchRangeStart = start;
        this.searchRangeEnd = end;
        return this;
    }

    /**
     * 设置目标函数名称（用于符号查找）
     */
    public UnidbgIndirectJumpDeobfuscator setFunctionName(String name) {
        this.functionName = name;
        return this;
    }

    /**
     * 设置目标函数偏移（直接使用偏移）
     */
    public UnidbgIndirectJumpDeobfuscator setFunctionOffset(long offset) {
        this.functionOffset = offset;
        return this;
    }

    /**
     * 设置环境补充回调（旧版本，兼容性保留）
     *
     * @param patcher 环境补充器，用于在运行时补充缺失的 JNI 函数
     * @return this
     * @deprecated 请使用 EmulatorManager.getEnvironmentManager().addPatcher()
     */
    @Deprecated
    public UnidbgIndirectJumpDeobfuscator setEnvironmentPatcher(EnvironmentPatcher patcher) {
        this.legacyEnvironmentPatcher = patcher;
        return this;
    }

    /**
     * 查找函数地址（通过符号名称）
     */
    private Long findFunctionAddress(String name) {
        com.github.unidbg.Symbol symbol = module.findSymbolByName(name);
        if (symbol != null && !symbol.isUndef()) {
            return symbol.getValue();
        }
        return null;
    }

    /**
     * 确定目标函数地址
     */
    private long determineFunctionAddress() {
        if (functionName != null) {
            Long address = findFunctionAddress(functionName);
            if (address == null) {
                log("警告：未找到函数符号 '" + functionName + "'");
                return -1;
            }
            return address;
        }

        if (functionOffset != -1) {
            return module.base + functionOffset;
        }

        // 默认返回入口点（向后兼容，但已废弃）
        return module.base + 0x10000;
    }

    /**
     * 执行去混淆（可重复调用）
     */
    public boolean deobfuscate() {
        try {
            // 清除之前的分析结果
            this.instructionStack.clear();
            this.patchList.clear();

            log("开始分析间接跳转...");
            log("模块基地址: 0x" + Long.toHexString(module.base));

            // 确定目标函数地址
            long functionAddress = determineFunctionAddress();
            if (functionAddress == -1) {
                log("错误：未指定目标函数。请使用 setFunctionName() 或 setFunctionOffset() 设置目标。");
                return false;
            }

            log("目标函数地址: 0x" + Long.toHexString(functionAddress));

            // 设置指令级 Hook
            setupInstructionHook();

            // 运行目标函数（可能需要多次尝试）
            int maxAttempts = 3;
            boolean success = false;
            Exception lastError = null;

            for (int attempt = 1; attempt <= maxAttempts && !success; attempt++) {
                try {
                    log("执行目标函数... (尝试 " + attempt + "/" + maxAttempts + ")");
                    module.callFunction(emulator, functionAddress);
                    success = true;
                } catch (Exception e) {
                    lastError = e;
                    log("执行失败: " + e.getMessage());

                    // 如果设置了环境补充器，尝试补充环境
                    if ((legacyEnvironmentPatcher != null ||
                         (emulatorManager != null && emulatorManager.getEnvironmentManager().hasPatchers())) &&
                        attempt < maxAttempts) {
                        String missingSymbol = extractMissingSymbol(e);
                        log("尝试补充环境... (缺失: " + (missingSymbol != null ? missingSymbol : "未知") + ")");

                        boolean patched = false;

                        // 优先使用 EmulatorManager 的环境补充器
                        if (emulatorManager != null) {
                            patched = emulatorManager.getEnvironmentManager().tryPatchEnvironment(
                                    emulator, module, missingSymbol);
                        }

                        // 如果失败，尝试旧版本的补充器
                        if (!patched && legacyEnvironmentPatcher != null) {
                            patched = legacyEnvironmentPatcher.patchEnvironment(emulator, module, missingSymbol);
                        }

                        if (patched) {
                            log("环境补充成功，重试...");
                            continue;
                        }
                    }
                    log("无法继续执行，放弃。");
                    break;
                }
            }

            if (!success && lastError != null) {
                log("去混淆失败: " + lastError.getMessage());
                if (verbose) {
                    lastError.printStackTrace();
                }
                return false;
            }

            // 生成 Patch 并应用
            applyPatches();

            log("完成去混淆！");
            log("输出文件: " + outputPath);
            log("总共生成 " + patchList.size() + " 个 Patch");

            return true;

        } catch (Exception e) {
            log("去混淆失败: " + e.getMessage());
            if (verbose) {
                e.printStackTrace();
            }
            return false;
        }
    }

    /**
     * 设置指令级 Hook 用于跟踪
     */
    private void setupInstructionHook() {
        long baseAddr = module.base;
        long startAddr = baseAddr + searchRangeStart;
        long endAddr = baseAddr + searchRangeEnd;

        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                try {
                    // 反汇编当前指令
                    Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
                    byte[] bytes = backend.mem_read(address, 4);
                    Instruction[] disasm = capstone.disasm(bytes, 0);

                    // 记录指令和寄存器状态
                    InstructionInfo info = new InstructionInfo();
                    info.address = address;
                    info.mnemonic = disasm[0].getMnemonic();
                    info.operands = disasm[0].getOpStr();
                    info.registers = saveRegisters(backend);
                    instructionStack.push(info);

                    // 处理指令（跳过一些特殊情况）
                    if (isSpecialInstruction(info.mnemonic, info.operands)) {
                        return;
                    }

                    // 检查是否是间接跳转
                    if (isIndirectJump(info.mnemonic, info.operands)) {
                        processIndirectJump(backend, info);
                    }

                } catch (Exception e) {
                    // 忽略异常，继续处理下一条指令
                    if (verbose) {
                        e.printStackTrace();
                    }
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                log("指令 Hook 已附加");
            }

            @Override
            public void detach() {
                log("指令 Hook 已分离");
            }
        }, startAddr, endAddr, null);
    }

    /**
     * 检查是否是特殊指令
     */
    private boolean isSpecialInstruction(String mnemonic, String operands) {
        return mnemonic.charAt(0) == 'b' || mnemonic.startsWith("bl") ||
               mnemonic.contains("ld") || mnemonic.contains("st");
    }

    /**
     * 处理间接跳转
     */
    private void processIndirectJump(Backend backend, InstructionInfo jumpInfo) {
        log("发现间接跳转: " + jumpInfo);

        try {
            // 指令栈回溯，分析跳转目标
            List<InstructionInfo> path = traceBackToAddressCalculation();

            if (path == null || path.isEmpty()) {
                log("未找到完整的跳转路径分析信息");
                return;
            }

            // 尝试获取跳转目标
            List<Long> targets = findJumpTargets(backend, path);
            if (targets.size() < 2) {
                log("未找到足够的跳转目标（需要至少2个）");
                return;
            }

            // 尝试找到条件指令
            String condition = findConditionInstruction(path);

            if (condition == null || condition.isEmpty()) {
                log("未找到条件指令，可能是无条件跳转");
                return;
            }

            // 计算偏移
            long brOffset = jumpInfo.address - module.base;

            // 生成 Patch 信息
            PatchInfo patch1 = new PatchInfo();
            patch1.address = brOffset - 4;  // 条件跳转地址
            patch1.instruction = String.format(Locale.ENGLISH, "b.%s 0x%x",
                    condition, calculateBranchOffset(brOffset - 4, targets.get(0) - module.base));
            patchList.add(patch1);

            PatchInfo patch2 = new PatchInfo();
            patch2.address = brOffset;  // 无条件跳转地址
            patch2.instruction = String.format(Locale.ENGLISH, "b 0x%x",
                    calculateBranchOffset(brOffset, targets.get(1) - module.base));
            patchList.add(patch2);

            log("生成 Patch: " + patch1);
            log("生成 Patch: " + patch2);

        } catch (Exception e) {
            log("处理间接跳转失败: " + e.getMessage());
            if (verbose) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 追踪指令栈，找到地址计算部分
     */
    private List<InstructionInfo> traceBackToAddressCalculation() {
        List<InstructionInfo> result = new ArrayList<>();
        boolean foundAddressLoad = false;

        // 创建反向迭代器
        Stack<InstructionInfo> tempStack = (Stack<InstructionInfo>) instructionStack.clone();

        while (!tempStack.isEmpty() && !foundAddressLoad) {
            InstructionInfo info = tempStack.pop();
            result.add(info);

            // 检查是否是地址加载指令
            if (info.mnemonic.equals("ldr") && info.operands.contains("uxtw #3")) {
                foundAddressLoad = true;
            }
        }

        return foundAddressLoad ? result : null;
    }

    /**
     * 计算跳转偏移
     */
    private int calculateBranchOffset(long srcOffset, long dstOffset) {
        int delta = (int) (dstOffset - srcOffset);
        return delta / 4;  // ARM64 指令是 4 字节对齐
    }

    /**
     * 从指令路径中查找条件
     */
    private String findConditionInstruction(List<InstructionInfo> path) {
        for (InstructionInfo info : path) {
            if (info.mnemonic.equals("csel")) {
                String[] parts = info.operands.split(",");
                if (parts.length > 3) {
                    String cond = parts[3].trim().toLowerCase(Locale.ROOT);
                    if (!cond.isEmpty()) {
                        return cond;
                    }
                }
            }
        }
        return null;
    }

    /**
     * 查找跳转目标
     */
    private List<Long> findJumpTargets(Backend backend, List<InstructionInfo> path) {
        List<Long> targets = new ArrayList<>();

        for (InstructionInfo info : path) {
            if (info.mnemonic.equals("ldr") && info.operands.contains("uxtw #3")) {
                long baseArrayAddr = parseBaseArrayAddress(info, backend);
                long[] offsets = parseIndicesFromCsel(path);

                for (long offset : offsets) {
                    long ptrAddr = baseArrayAddr + offset * 8;
                    long targetAddr = readQword(backend, ptrAddr);

                    if (isValidCodeAddress(targetAddr)) {
                        targets.add(targetAddr);
                    }
                }
                break;
            }
        }

        return targets;
    }

    /**
     * 从 CSEL 指令中解析索引值
     */
    private long[] parseIndicesFromCsel(List<InstructionInfo> path) {
        for (InstructionInfo info : path) {
            if (info.mnemonic.equals("csel")) {
                return extractCselRegisters(info, path);
            }
        }
        return new long[]{0, 1};  // 默认索引
    }

    /**
     * 提取 CSEL 指令的寄存器值
     */
    private long[] extractCselRegisters(InstructionInfo cselInfo, List<InstructionInfo> context) {
        String[] parts = cselInfo.operands.split(",");
        if (parts.length > 2) {
            String reg1 = parts[1].trim();
            String reg2 = parts[2].trim();

            long value1 = getRegisterValue(reg1, cselInfo.registers);
            long value2 = getRegisterValue(reg2, cselInfo.registers);

            return new long[]{value1, value2};
        }

        return new long[]{0, 1};
    }

    /**
     * 解析基地址数组
     */
    private long parseBaseArrayAddress(InstructionInfo info, Backend backend) {
        String[] parts = info.operands.split(",");
        if (parts.length > 1) {
            String reg = parts[1].trim();

            // 解析寄存器名称
            if (reg.startsWith("x") || reg.startsWith("w")) {
                long regValue = getRegisterValue(reg, info.registers);
                // 检查是否在模块范围内
                if (isValidModuleAddress(regValue)) {
                    return regValue;
                }
            }
        }

        return module.base + 0x400000;  // 默认地址
    }

    /**
     * 保存寄存器状态
     */
    private List<Number> saveRegisters(Backend backend) {
        List<Number> registers = new ArrayList<>();

        // 保存 x0-x28
        for (int i = 0; i < 29; i++) {
            registers.add(backend.reg_read(Arm64Const.UC_ARM64_REG_X0 + i));
        }

        // 保存 FP 和 LR
        registers.add(backend.reg_read(Arm64Const.UC_ARM64_REG_FP));
        registers.add(backend.reg_read(Arm64Const.UC_ARM64_REG_LR));

        return registers;
    }

    /**
     * 从保存的寄存器中获取值
     */
    private long getRegisterValue(String reg, List<Number> registers) {
        if (reg.equals("xzr")) {
            return 0;
        }

        try {
            String regName = reg.toLowerCase(Locale.ROOT);
            int index = Integer.parseInt(regName.substring(1));

            if (regName.startsWith("w")) {
                // 32 位寄存器
                return registers.get(index).longValue() & 0xffffffffL;
            } else if (regName.startsWith("x")) {
                // 64 位寄存器
                return registers.get(index).longValue();
            }
        } catch (Exception e) {
            // 忽略解析失败
        }

        return 0;
    }

    /**
     * 判断地址是否是有效的代码地址
     */
    private boolean isValidCodeAddress(long address) {
        long textStart = module.base;
        long textEnd = module.base + module.size;
        return address >= textStart && address < textEnd;
    }

    /**
     * 判断地址是否是有效的模块地址
     */
    private boolean isValidModuleAddress(long address) {
        return address >= module.base && address < module.base + module.size;
    }

    /**
     * 读取 64 位数据
     */
    private long readQword(Backend backend, long address) {
        byte[] data = backend.mem_read(address, 8);
        return (long) (data[7] & 0xff) << 56 |
               (long) (data[6] & 0xff) << 48 |
               (long) (data[5] & 0xff) << 40 |
               (long) (data[4] & 0xff) << 32 |
               (long) (data[3] & 0xff) << 24 |
               (long) (data[2] & 0xff) << 16 |
               (long) (data[1] & 0xff) << 8 |
               (data[0] & 0xff);
    }

    /**
     * 检查是否是间接跳转
     */
    private boolean isIndirectJump(String mnemonic, String operands) {
        return (mnemonic.equals("br") || mnemonic.equals("blr")) && operands.startsWith("x");
    }

    /**
     * 应用 Patch 到文件
     */
    private void applyPatches() {
        try {
            byte[] fileData = readFile(inputPath);
            byte[] patchedData = applyPatchesToData(fileData);
            writeFile(outputPath, patchedData);
        } catch (Exception e) {
            throw new RuntimeException("Patch 失败: " + e.getMessage(), e);
        }
    }

    /**
     * 将 Patch 应用到字节数组
     */
    private byte[] applyPatchesToData(byte[] data) {
        byte[] patched = data.clone();

        log("应用 " + patchList.size() + " 个 Patch...");

        for (PatchInfo patch : patchList) {
            try {
                byte[] machineCode = assembleInstruction(patch.instruction);

                log("Patch @ " + String.format("0x%x: %s (%d bytes)",
                        patch.address, patch.instruction, machineCode.length));

                // 验证写入位置
                if (patch.address + machineCode.length > patched.length) {
                    log("Patch 超出文件范围，跳过: " + patch);
                    continue;
                }

                // 写入机器码
                System.arraycopy(machineCode, 0, patched, (int) patch.address, machineCode.length);

            } catch (Exception e) {
                log("Patch 指令失败: " + patch + ", 错误: " + e.getMessage());
                if (verbose) {
                    e.printStackTrace();
                }
            }
        }

        return patched;
    }

    /**
     * 汇编指令为机器码
     */
    private byte[] assembleInstruction(String assembly) throws Exception {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble(assembly);
            if (encoded.getMachineCode().length > 4) {
                throw new IllegalArgumentException("指令长度超过 4 字节");
            }
            return encoded.getMachineCode();
        }
    }

    /**
     * 读取文件
     */
    private byte[] readFile(String path) throws IOException {
        File file = new File(path);
        byte[] buffer = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(buffer);
        }
        return buffer;
    }

    /**
     * 写入文件
     */
    private void writeFile(String path, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(data);
        }
    }

    /**
     * 清理资源
     */
    private void cleanup() {
        // 只关闭自己创建的模拟器
        if (ownsEmulator) {
            try {
                this.emulator.close();
            } catch (IOException e) {
                // 忽略关闭异常
            }
        }
    }

    /**
     * 从异常中提取缺失的符号名称
     */
    private String extractMissingSymbol(Exception e) {
        String msg = e.getMessage();
        if (msg == null) {
            return null;
        }

        // Pattern: "find symbol failed: <symbol_name>"
        if (msg.contains("find symbol failed")) {
            int start = msg.indexOf(':');
            if (start != -1) {
                return msg.substring(start + 1).trim();
            }
        }

        return null;
    }

    /**
     * 日志输出
     */
    private void log(String message) {
        if (verbose) {
            System.out.println("[OLLVM] " + message);
        }
    }

    /**
     * 生成输出路径
     */
    private static String generateOutputPath(String inputPath) {
        int dotIndex = inputPath.lastIndexOf('.');
        if (dotIndex != -1) {
            return inputPath.substring(0, dotIndex) + DEFAULT_OUTPUT_SUFFIX + inputPath.substring(dotIndex);
        }
        return inputPath + DEFAULT_OUTPUT_SUFFIX;
    }

    /**
     * 指令信息类
     */
    private static class InstructionInfo {
        long address;
        String mnemonic;
        String operands;
        List<Number> registers;

        @Override
        public String toString() {
            return String.format("0x%x: %s %s", address, mnemonic, operands);
        }
    }

    /**
     * Patch 信息类
     */
    public static class PatchInfo {
        long address;
        String instruction;

        @Override
        public String toString() {
            return String.format("0x%x: %s", address, instruction);
        }
    }

    /**
     * 使用示例
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("OLLVM 间接跳转反混淆工具");
            System.out.println("用法: java UnidbgIndirectJumpDeobfuscator <so_file_path> [选项]");
            System.out.println();
            System.out.println("选项:");
            System.out.println("  -o <output_path>     指定输出文件路径");
            System.out.println("  -f <function_name>    按符号名称指定目标函数");
            System.out.println("  -x <offset>           按偏移指定目标函数（十六进制）");
            System.out.println("  -r <start>-<end>      设置搜索范围（十六进制偏移）");
            System.out.println("  -v                    启用详细输出");
            System.out.println();
            System.out.println("示例:");
            System.out.println("  java UnidbgIndirectJumpDeobfuscator libobfuscated.so -f target_function");
            System.out.println("  java UnidbgIndirectJumpDeobfuscator libobfuscated.so -x 0x10000 -o lib_patched.so");
            return;
        }

        String inputPath = args[0];
        String outputPath = null;
        String functionName = null;
        Long functionOffset = null;
        int searchStart = 0;
        int searchEnd = Integer.MAX_VALUE;
        boolean verbose = true;

        // 解析参数
        for (int i = 1; i < args.length; i++) {
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

        // 执行去混淆
        boolean success = deobfuscator.deobfuscate();

        System.out.println("\n去混淆结果: " + (success ? "成功" : "失败"));
        if (success) {
            System.out.println("输出文件: " + deobfuscator.outputPath);
        }
    }
}