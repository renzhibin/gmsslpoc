package org.poc;

/**
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import org.gmssl.Sm3Hmac;
import org.gmssl.Random;
import org.poc.common.Tools;

import java.io.File;
import java.io.FileInputStream;
import java.util.Base64;

public class HMACPOC {

    public static void main(String[] args) throws NoSuchAlgorithmException {


        String FilePath = System.getProperty("user.dir") + "/src/main/resources/";

        byte[] pemBytes=readPem(FilePath+"ca/subcacert.pem");

        byte[] mac= generateMac(pemBytes);

        writeMac(FilePath+"mac1.bin",mac );
      //  writeMac(FilePath+"mac.bin",mac );


    }

    public static byte[] generateMac(byte[] pemBytes) throws NoSuchAlgorithmException {
//        Random rng = new Random();
//        byte[] key = rng.randBytes(Sm3Hmac.MAC_SIZE);
//        SecureRandom rng = SecureRandom.getInstanceStrong();
//        rng.setSeed(123456789L); // 设置一个固定的种子
//        byte[] key = new byte[Sm3Hmac.MAC_SIZE];
//        rng.nextBytes(key); // 使用 nextBytes 填充数组
        byte[] key = {0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB,  (byte) 0xCD, (byte) 0xEF, 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF};

        Sm3Hmac sm3hmac = new Sm3Hmac(key);

        sm3hmac.update(pemBytes, 0, pemBytes.length);
        byte[] mac = sm3hmac.generateMac();
        return  mac;


    }
    public  static    byte[]   readPem(String pemFilePath){
        byte[] pemBytes =null;
     try {
         File pemFile = new File(pemFilePath);
         FileInputStream fis = new FileInputStream(pemFile);
         pemBytes = fis.readAllBytes(); // 注意：readAllBytes() 在Java 9及以上版本中可用
         fis.close();

     }catch (IOException e){
         e.printStackTrace();
     }
        return  pemBytes;

    }
    public static void   writeMac(String filename, byte[] mac) {
        // 创建一个FileOutputStream来写入文件
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            // 将mac字节数组写入文件
            fos.write(mac);

            // 刷新输出流（虽然对于FileOutputStream来说，在close时会自动刷新，但显式调用也无害）
            fos.flush();


            System.out.println("MAC值已成功写入文件"+filename);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("写入MAC值时发生错误。");
        }
    }
}

