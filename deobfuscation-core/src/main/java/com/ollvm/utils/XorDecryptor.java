package com.ollvm.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 通用 XOR 解密工具
 */
public class XorDecryptor {

    public static final byte[] XOR_KEY_0 = new byte[]{0x00, 0x00, 0x00, 0x00};
    public static final byte[] XOR_KEY_55AA = new byte[]{0x55, (byte) 0xAA, 0x55, (byte) 0xAA};
    public static final byte[] XOR_KEY_AA55 = new byte[]{(byte) 0xAA, 0x55, (byte) 0xAA, 0x55};
    public static final byte[] XOR_KEY_1234 = new byte[]{0x12, 0x34, 0x56, 0x78};

    /**
     * 通用 XOR 解密
     *
     * @param data 加密数据
     * @param key  解密密钥
     * @return 解密后的数据
     */
    public static byte[] xorDecrypt(byte[] data, byte[] key) {
        if (data == null || data.length == 0) {
            return new byte[0];
        }
        if (key == null || key.length == 0) {
            return data.clone();
        }

        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    /**
     * 使用多个密钥尝试解密，返回最佳匹配
     *
     * @param data          加密数据
     * @param keyCandidates 候选密钥列表
     * @return 最佳解密结果
     */
    public static DecryptionResult tryMultipleKeys(byte[] data, List<byte[]> keyCandidates) {
        DecryptionResult bestResult = null;

        for (byte[] key : keyCandidates) {
            byte[] decrypted = xorDecrypt(data, key);
            int score = evaluateDecryption(decrypted);

            if (bestResult == null || score > bestResult.score) {
                bestResult = new DecryptionResult(key, decrypted, score);
            }
        }

        return bestResult;
    }

    /**
     * 评估解密结果的质量
     *
     * @param data 解密后的数据
     * @return 质量分数（越高越好）
     */
    public static int evaluateDecryption(byte[] data) {
        int score = 0;
        int printableCount = 0;
        int nullCount = 0;

        for (byte b : data) {
            // 可打印 ASCII 字符
            if ((b >= 0x20 && b <= 0x7E)) {
                printableCount++;
                score += 2;
            }
            // 常见控制字符
            else if (b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0D) {
                if (b == 0x00) nullCount++;
                score += 1;
            }
            // 其他字符
            else {
                score -= 1;
            }
        }

        // 字符串通常以 null 结尾
        if (nullCount > 0) {
            score += 5;
        }

        // 确保有一定比例的可打印字符
        float printableRatio = (float) printableCount / data.length;
        if (printableRatio < 0.4) {
            score -= 50;
        }

        return score;
    }

    /**
     * 尝试自动识别密钥
     *
     * @param data          加密数据
     * @param maxKeyLength 最大尝试的密钥长度
     * @return 找到的密钥
     */
    public static byte[] autoDetectKey(byte[] data, int maxKeyLength) {
        byte[] bestKey = null;
        int bestScore = Integer.MIN_VALUE;

        for (int keyLen = 1; keyLen <= maxKeyLength; keyLen++) {
            // 尝试一些常见的密钥
            for (byte[] pattern : generateKeyPatterns(keyLen)) {
                byte[] decrypted = xorDecrypt(data, pattern);
                int score = evaluateDecryption(decrypted);

                if (score > bestScore) {
                    bestScore = score;
                    bestKey = pattern.clone();
                }
            }
        }

        return bestKey;
    }

    /**
     * 生成密钥模式
     *
     * @param length 密钥长度
     * @return 密钥模式列表
     */
    private static List<byte[]> generateKeyPatterns(int length) {
        List<byte[]> patterns = new ArrayList<>();

        // 单字节模式
        byte[] singleByte = new byte[length];
        for (byte b = 0; b <= 0xFF; b++) {
            Arrays.fill(singleByte, b);
            patterns.add(singleByte.clone());
        }

        // 交替模式
        if (length >= 2) {
            byte[] alt = new byte[length];
            for (int i = 0; i < length; i++) {
                alt[i] = (i % 2 == 0) ? (byte) 0x55 : (byte) 0xAA;
            }
            patterns.add(alt.clone());
        }

        // 递增模式
        byte[] increment = new byte[length];
        for (int i = 0; i < length; i++) {
            increment[i] = (byte) i;
        }
        patterns.add(increment.clone());

        return patterns;
    }

    /**
     * 从文件加载加密数据并解密
     *
     * @param inputFile  输入文件
     * @param key        密钥
     * @param outputFile 输出文件
     * @throws IOException IO错误
     */
    public static void decryptFile(String inputFile, byte[] key, String outputFile)
            throws IOException {
        byte[] data = Files.readAllBytes(Paths.get(inputFile));
        byte[] decrypted = xorDecrypt(data, key);
        Files.write(Paths.get(outputFile), decrypted);
    }

    /**
     * 解密结果类
     */
    public static class DecryptionResult {
        public byte[] key;
        public byte[] data;
        public int score;

        public DecryptionResult(byte[] key, byte[] data, int score) {
            this.key = key;
            this.data = data;
            this.score = score;
        }

        public String getKeyHex() {
            StringBuilder sb = new StringBuilder();
            for (byte b : key) {
                sb.append(String.format("%02x ", b));
            }
            return sb.toString().trim();
        }

        public String getDataAsString() {
            return new String(data, StandardCharsets.UTF_8);
        }

        @Override
        public String toString() {
            return "DecryptionResult(score=" + score + ", key=" + getKeyHex() + ")";
        }
    }

    public static void main(String[] args) {
        System.out.println("=== XOR 解密工具 ===\n");

        // 测试数据
        String testData = "Hello, OLLVM World!";
        byte[] originalData = testData.getBytes(StandardCharsets.UTF_8);

        // 使用一个密钥加密
        byte[] key = XOR_KEY_55AA;
        byte[] encryptedData = xorDecrypt(originalData, key);

        System.out.println("测试原始字符串: " + testData);
        System.out.println("使用的密钥: " + new DecryptionResult(key, null, 0).getKeyHex());
        System.out.println("加密后的十六进制: " + bytesToHex(encryptedData));
        System.out.println();

        // 尝试解密
        System.out.println("尝试自动解密...");

        List<byte[]> keyCandidates = Arrays.asList(
                XOR_KEY_0,
                XOR_KEY_55AA,
                XOR_KEY_AA55,
                XOR_KEY_1234
        );

        DecryptionResult result = tryMultipleKeys(encryptedData, keyCandidates);

        if (result != null) {
            System.out.println("找到最佳解密结果:");
            System.out.println("  密钥: " + result.getKeyHex());
            System.out.println("  分数: " + result.score);
            System.out.println("  解密结果: " + result.getDataAsString());
        } else {
            System.out.println("解密失败");
        }

        System.out.println();
        System.out.println("工具使用示例:");
        System.out.println("  XorDecryptor.xorDecrypt(data, key)");
        System.out.println("  XorDecryptor.tryMultipleKeys(data, keyList)");
        System.out.println("  XorDecryptor.autoDetectKey(data, maxKeyLength)");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}