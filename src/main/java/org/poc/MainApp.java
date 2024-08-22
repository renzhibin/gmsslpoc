package org.poc;
/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


import org.gmssl.Sm2Key;
import org.gmssl.Sm2Signature;
import org.gmssl.Sm3;

import org.poc.common.PrasePEM;
import org.poc.common.Tools;
import org.poc.datareceive.DataReceiveApp;
import org.poc.datasend.DataSendApp;

public class MainApp {

    /*
     0. 数据证书（见resources/gmssl.sh 脚本）
       0.0 生成根证书
       0.1 生成子证书
       0.2 生成三端签名证书

     1.发送方：
       1.1.发送方生成会话对称密钥（SM4)sessionKey，并对消息orgData（I am a test message ）进行加密，生成密文encData
       1.2.发送方使用接收方的公钥receiverPubKey加密sessionKey，生成数字信封encSessionKey
       1.3.发送方对encData进行Hash，生成信息摘要hashData
       1.4.发送方使用发送方的私钥对hashData进行签名，生成数字签名signData
       1.5 发送方将encSessionKey、encData和signData发送给DTMS

     2.DTMS
       2.1 DTMS验证发送方数据证书和CA证书 -- 定时调度即可
       2.2 DTMS使用发送方的公钥sendPubKey解密数字签名signData，得到信息摘要hashData
       2.3 DTMS对encData进行Hash，得到信息摘要dHashData，与hashData比较，如果相等，则证明数据没有被修改

     3.接收方
       3.1 -3.3 同 2.1-2.3

       3.4 接收方使用自己的私钥receiverPriKey解密数字信封encSessionKey，得到sessionKey
       3.5 接收方使用sessionKey解密密文encData，得到明文orgData

     */
    public static void main(String[] args) {

      /*  1.发送方：
      */
        DataSendApp dataSendApp = new DataSendApp();
        DataReceiveApp dataReceiveApp = new DataReceiveApp();


        System.out.println("*".repeat(10)+"DataSend Start"+"*".repeat(10));

        String orgData = "I am a test message";
        System.out.println("1.1 发送方生成会话对称密钥（SM4)sessionKey，并对消息orgData（I am a test message ）进行加密，生成密文encData");
        Object[] result=dataSendApp.encData(orgData);
        byte[] encData = (byte[]) result[0];
        int encDataLength = (int) result[1];

        System.out.println("1.2.发送方使用接收方的公钥receiverPubKey加密sessionKey，生成数字信封encSessionKey");
        byte[] encSessionKey  = dataReceiveApp.pubKey.encrypt(dataSendApp.sessionKey);
        System.out.println("1.3.发送方对encData进行Hash，生成数字指纹hashData；发送方使用发送方的私钥对hashData进行签名，生成数字签名signData");
        byte[] hashData=Tools.sm3hash(encData);//获取哈希值
        Sm2Signature sm2Signature = new Sm2Signature(dataSendApp.priKey, "dataSendApp", true);
        sm2Signature.update(hashData);
        byte[]  signData = sm2Signature.sign();
        System.out.println("*".repeat(10)+"DataSend finshed"+"*".repeat(10));

    /*
       2.DTMS

    */
        System.out.println("*".repeat(10)+"DTMS  Start"+"*".repeat(10));

        System.out.println("2.1 DTMS验证发送方数据证书和CA证书 --- 定时调度即可");
        PrasePEM datasendCert = new PrasePEM("datasendcert.pem");
        System.out.println("证书验证结果： " + datasendCert.verifycert("datasendcert.pem"));


        System.out.println("2.2 DTMS使用发送方的公钥sendPubKey解密数字签名signData，得到信息摘要hashData");
        System.out.println("2.3 DTMS对encData进行Hash，得到信息摘要dHashData，与hashData比较，如果相等，则证明数据没有被修改");

        byte[] dhashData=Tools.sm3hash(encData);//获取哈希值

        Sm2Signature verify = new Sm2Signature(dataSendApp.pubKey, "dataSendApp", false);
        verify.update(dhashData);
        System.out.println("数据签名验证结果： " + verify.verify(signData));

        System.out.println("*".repeat(10)+"DTMS finshed"+"*".repeat(10));



/*
        3.接收方

  */
        System.out.println("*".repeat(10)+"DataReceive Start"+"*".repeat(10));

        System.out.println("3.1 -3.3 同 2.1-2.3");

        System.out.println("3.4 接收方使用自己的私钥receiverPriKey解密数字信封encSessionKey，得到sessionKey");
        byte[]  sessionKey = dataReceiveApp.priKey.decrypt(encSessionKey);
        System.out.println("3.5 接收方使用sessionKey解密密文encData，得到明文orgData");
        //todo:encDataLength是否必传
        orgData=dataReceiveApp.decData(encData,sessionKey, encDataLength);
        System.out.println("The orgData is : " + orgData);

        System.out.println("*".repeat(10)+"DataReceive finshed"+"*".repeat(10));



        System.out.println("The POC  is  finished");
    }


}
