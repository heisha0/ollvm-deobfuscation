package com.ollvm.stringencryption;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import capstone.Capstone;
import capstone.api.Instruction;
import unicorn.Arm64Const;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * OLLVM 字符串加密反混淆器 - Unidbg 实现
 * 用于处理字符串加密混淆
 */
public class UnidbgStringDecryptor {

    private static final String DEFAULT_OUTPUT_SUFFIX = "_decrypted";
    private static final int MAX_STRING_LENGTH = 512;

    private final AndroidEmulator emulator;
    private final Module module;
    private final String inputPath;
    private final String outputPath;

    private boolean verbose = true;
    private List<DecryptedString> decryptedStrings;
    private Map<Long, String> stringCache;
    private Set<Long> decryptFunctionAddresses;

    public UnidbgStringDecryptor(String inputPath) {
        this(inputPath, generateOutputPath(inputPath));
    }

    public UnidbgStringDecryptor(String inputPath, String outputPath) {
        this.inputPath = inputPath;
        this.outputPath = outputPath;

        try {
            this.emulator = AndroidEmulatorBuilder.for64Bit()
                    .setProcessName("com.ollvm.stringdecrypt")
                    .build();

            Memory memory = this.emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(28));

            VM vm = this.emulator.createDalvikVM();
            vm.setVerbose(false);

            File libFile = new File(inputPath);
            DalvikModule dm = vm.loadLibrary(libFile, false);
            this.module = dm.getModule();

            this.decryptedStrings = new ArrayList<>();
            this.stringCache = new HashMap<>();
            this.decryptFunctionAddresses = new HashSet<>();

        } catch (Exception e) {
            throw new RuntimeException("初始化失败: " + e.getMessage(), e);
        }
    }

    public UnidbgStringDecryptor setVerbose(boolean verbose) {
        this.verbose = verbose;
        return this;
    }

    public boolean decrypt() {
        try {
            log("开始分析字符串加密...");

            // 1. 识别解密函数
            findDecryptFunctions();

            if (decryptFunctionAddresses.isEmpty()) {
                log("未找到解密函数，尝试通用方法");
                findGenericDecryptFunctions();
            }

            if (decryptFunctionAddresses.isEmpty()) {
                log("未识别到任何解密函数模式");
                return false;
            }

            log("识别到 " + decryptFunctionAddresses.size() + " 个解密函数候选");

            // 2. 钩子解密函数
            hookDecryptFunctions();

            // 3. 运行初始化以触发解密
            runInitialization();

            // 4. 处理解密结果
            processDecryptedStrings();

            log("解密完成！");
            log("找到 " + decryptedStrings.size() + " 个字符串");
            log("输出文件: " + outputPath);

            writeDecryptionReport();
            return true;

        } catch (Exception e) {
            log("解密失败: " + e.getMessage());
            e.printStackTrace();
            return false;

        } finally {
            cleanup();
        }
    }

    private void findDecryptFunctions() {
        // 基于常见解密函数命名模式查找
        List<String> patterns = Arrays.asList(
                "goron_decrypt_string", "decrypt_string", "deobfuscate",
                "decode", "unpack", "cipher", "crypt"
        );

        module.enumerateSymbols().stream()
                .filter(symbol -> patterns.stream().anyMatch(p ->
                        symbol.getName().toLowerCase().contains(p)))
                .forEach(symbol -> {
                    decryptFunctionAddresses.add(module.base + symbol.getAddress());
                    log("找到解密函数符号: " + symbol.getName());
                });
    }

    private void findGenericDecryptFunctions() {
        long baseAddr = module.base;
        long startAddr = baseAddr;
        long endAddr = baseAddr + module.size;

        // 查找包含 XOR 操作的函数
        long currentAddr = startAddr;
        while (currentAddr < endAddr) {
            if (containsXorPattern(currentAddr)) {
                long funcStart = findFunctionStart(currentAddr);
                decryptFunctionAddresses.add(funcStart);
                log("找到包含 XOR 的函数: 0x" + Long.toHexString(funcStart));
                currentAddr = findFunctionEnd(funcStart);
            } else {
                currentAddr += 4;
            }
        }
    }

    private boolean containsXorPattern(long address) {
        try {
            Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
            byte[] buffer = new byte[0x400];
            int bytesRead = Math.min(0x400, (int)(module.base + module.size - address));
            if (bytesRead <= 0) return false;

            buffer = emulator.getBackend().mem_read(address, bytesRead);
            Instruction[] disasm = capstone.disasm(buffer, 0);

            int xorCount = 0;
            for (Instruction ins : disasm) {
                if (ins.getMnemonic().equals("eor")) {
                    if (++xorCount >= 2) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            // 忽略错误
        }
        return false;
    }

    private long findFunctionStart(long addr) {
        while (addr > module.base) {
            if (isFunctionStart(addr)) {
                return addr;
            }
            addr -= 4;
        }
        return module.base;
    }

    private boolean isFunctionStart(long addr) {
        return addr == module.base || isBranchTarget(addr);
    }

    private boolean isBranchTarget(long addr) {
        int branchPatternCount = 0;
        long checkRange = 0x100;

        for (long i = module.base; i < module.base + module.size; i += 4) {
            try {
                byte[] ins = emulator.getBackend().mem_read(i, 4);
                if (isBranchInstruction(ins)) {
                    long branchTarget = calculateBranchTarget(i, ins);
                    if (branchTarget == addr) {
                        branchPatternCount++;
                        if (branchPatternCount >= 1) return true;
                    }
                }
            } catch (Exception e) {
                continue;
            }
        }
        return false;
    }

    private boolean isBranchInstruction(byte[] instruction) {
        if (instruction.length < 4) return false;
        int word = instruction[0] & 0xFF | (instruction[1] & 0xFF) << 8 |
                  (instruction[2] & 0xFF) << 16 | (instruction[3] & 0xFF) << 24;

        return (word & 0xFC000000) == 0x14000000;
    }

    private long calculateBranchTarget(long address, byte[] instruction) {
        int word = instruction[0] & 0xFF | (instruction[1] & 0xFF) << 8 |
                  (instruction[2] & 0xFF) << 16 | (instruction[3] & 0xFF) << 24;

        int offset = word & 0x3FFFFFF;
        offset = (offset << 6) >> 6;
        return address + offset * 4;
    }

    private long findFunctionEnd(long start) {
        long current = start;

        while (current < module.base + module.size) {
            if (isFunctionEnd(current)) {
                return current;
            }
            current += 4;
        }

        return module.base + module.size;
    }

    private boolean isFunctionEnd(long addr) {
        try {
            byte[] buffer = emulator.getBackend().mem_read(addr, 8);
            int word1 = buffer[0] & 0xFF | (buffer[1] & 0xFF) << 8 |
                      (buffer[2] & 0xFF) << 16 | (buffer[3] & 0xFF) << 24;
            int word2 = buffer[4] & 0xFF | (buffer[5] & 0xFF) << 8 |
                      (buffer[6] & 0xFF) << 16 | (buffer[7] & 0xFF) << 24;

            if ((word1 & 0xFF00001F) == 0xD65F0000) {
                return true;
            }
        } catch (Exception e) {
            // 忽略错误
        }

        return false;
    }

    private void hookDecryptFunctions() {
        for (long funcAddr : decryptFunctionAddresses) {
            hookDecryptFunction(funcAddr);
        }
    }

    private void hookDecryptFunction(long funcAddr) {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                String funcName = module.enumerateSymbols().stream()
                        .filter(s -> module.base + s.getAddress() == address)
                        .map(s -> s.getName())
                        .findFirst().orElse("0x" + Long.toHexString(address));

                log("解密函数调用: " + funcName);

                // 记录函数调用上下文
                long outputPtr = backend.reg_read(Arm64Const.UC_ARM64_REG_X0);
                long inputPtr = backend.reg_read(Arm64Const.UC_ARM64_REG_X1);

                log("  输出缓冲区: 0x" + Long.toHexString(outputPtr));
                log("  输入数据: 0x" + Long.toHexString(inputPtr));

                // 记录参数以在返回时读取
                ((Map<Long, Long>) user).put(outputPtr, inputPtr);

            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, funcAddr, funcAddr + 4, new HashMap<Long, Long>());
    }

    private void runInitialization() {
        try {
            long entryPoint = findInitializationEntry();
            log("运行初始化入口: 0x" + Long.toHexString(entryPoint));
            module.callFunction(emulator, entryPoint);
        } catch (Exception e) {
            log("初始化失败，使用默认入口: 0x10000");
            module.callFunction(emulator, 0x10000);
        }
    }

    private long findInitializationEntry() {
        Optional<Long> ctor = module.enumerateSymbols().stream()
                .filter(s -> s.getName().startsWith("_init"))
                .map(s -> module.base + s.getAddress())
                .findFirst();

        return ctor.orElse(module.base + 0x10000);
    }

    private void processDecryptedStrings() {
        scanDecryptedMemory();
    }

    private void scanDecryptedMemory() {
        log("扫描已解密内存...");

        // 遍历内存区域
        for (long start = module.base; start < module.base + module.size; start += 0x1000) {
            try {
                byte[] buffer = emulator.getBackend().mem_read(start, 0x1000);

                int i = 0;
                while (i < buffer.length - 1) {
                    // 查找可能的字符串
                    int startIdx = i;
                    int endIdx = findStringEnd(buffer, startIdx);

                    if (endIdx - startIdx >= 4 && endIdx - startIdx < MAX_STRING_LENGTH) {
                        String string = extractString(buffer, startIdx, endIdx);
                        if (isValidString(string)) {
                            DecryptedString decrypted = new DecryptedString(start + startIdx, string);
                            if (!decryptedStrings.contains(decrypted)) {
                                decryptedStrings.add(decrypted);
                            }
                        }
                    }
                    i = endIdx + 1;
                }
            } catch (Exception e) {
                // 跳过不可读区域
                continue;
            }
        }
    }

    private int findStringEnd(byte[] buffer, int start) {
        int i = start;
        while (i < buffer.length && buffer[i] != 0) {
            i++;
        }
        return i;
    }

    private String extractString(byte[] buffer, int start, int end) {
        byte[] strBytes = new byte[end - start];
        System.arraycopy(buffer, start, strBytes, 0, end - start);
        return new String(strBytes);
    }

    private boolean isValidString(String str) {
        if (str.length() < 4) return false;

        int printableCount = 0;
        for (char c : str.toCharArray()) {
            if ((c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t') {
                printableCount++;
            }
        }

        return printableCount >= str.length() * 0.5;
    }

    private void writeDecryptionReport() throws IOException {
        File reportFile = new File(outputPath);
        try (PrintWriter writer = new PrintWriter(new FileWriter(reportFile))) {
            writer.println("OLLVM 字符串解密报告");
            writer.println("======================");
            writer.println("输入文件: " + inputPath);
            writer.println("输出文件: " + outputPath);
            writer.println("解密时间: " + new Date());
            writer.println("发现字符串数量: " + decryptedStrings.size());
            writer.println();

            // 按地址排序
            decryptedStrings.sort(Comparator.comparingLong(DecryptedString::getAddress));

            for (DecryptedString string : decryptedStrings) {
                writer.println("0x" + Long.toHexString(string.address) + ": " + formatString(string));
            }
        }
    }

    private String formatString(DecryptedString string) {
        String result = string.value;
        result = result.replace("\n", "\\n")
                      .replace("\r", "\\r")
                      .replace("\t", "\\t");
        return result;
    }

    private void cleanup() {
        try {
            this.emulator.close();
        } catch (IOException e) {
            // 忽略错误
        }
    }

    private void log(String message) {
        if (verbose) {
            System.out.println("[STRING] " + message);
        }
    }

    private static String generateOutputPath(String inputPath) {
        int dotIndex = inputPath.lastIndexOf('.');
        String name = dotIndex != -1 ? inputPath.substring(0, dotIndex) : inputPath;
        return name + DEFAULT_OUTPUT_SUFFIX + ".txt";
    }

    public static class DecryptedString {
        public long address;
        public String value;

        public DecryptedString(long address, String value) {
            this.address = address;
            this.value = value;
        }

        public long getAddress() {
            return address;
        }

        public String getValue() {
            return value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            DecryptedString that = (DecryptedString) o;
            return address == that.address && value.equals(that.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(address, value);
        }
    }

    public List<DecryptedString> getDecryptedStrings() {
        return Collections.unmodifiableList(decryptedStrings);
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("用法: java UnidbgStringDecryptor <so_file_path> [output_file]");
            System.out.println("示例: java UnidbgStringDecryptor libobfuscated.so");
            return;
        }

        String inputPath = args[0];
        String outputPath = args.length > 1 ? args[1] : null;

        UnidbgStringDecryptor decryptor =
                outputPath != null ? new UnidbgStringDecryptor(inputPath, outputPath)
                                   : new UnidbgStringDecryptor(inputPath);

        decryptor.setVerbose(true);
        boolean success = decryptor.decrypt();

        if (success) {
            System.out.println("\n成功解密 " + decryptor.decryptedStrings.size() + " 个字符串");

            if (args.length == 1) {
                System.out.println("解密报告已生成: " + decryptor.outputPath);
            }

            System.out.println("\n发现的字符串:");
            decryptor.decryptedStrings.forEach(s ->
                    System.out.printf("0x%x: %s\n", s.address, s.value));
        }
    }
}