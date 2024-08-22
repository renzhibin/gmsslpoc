package org.poc.common;

import org.gmssl.Sm3;

public class Tools {
    public static void printString(String[] str) {
        // System.out.println(title);
        for (String part : str) {
            System.out.print(part + " ");
        }
        System.out.println();
    }


    public static void printHex(String title, byte[] bytes) {
        System.out.printf(title + ":");
        int i;
        for (i = 0; i < bytes.length; i++) {
            System.out.printf("%02x", bytes[i]);
        }
        System.out.print("\n");
    }

    public static byte[] sm3hash(byte[] encData) {
        Sm3 sm3 = new Sm3();
        sm3.update(encData, 0, encData.length);
        byte[] hashData = sm3.digest(); // 获取哈希值
        return hashData;
    }
}