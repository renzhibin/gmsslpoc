package org.poc.common;

import org.gmssl.GmSSLException;
import org.gmssl.Sm2Certificate;
import org.gmssl.Sm2Key;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

public class PrasePEM
{
    Sm2Key priKey = new Sm2Key();
    Sm2Key pubKey = new Sm2Key();
    String resourcePath = System.getProperty("user.dir") + "/src/main/resources/";

    public PrasePEM(String filename){
        verifycert(filename);
    }
    public   Sm2Key getPriKey(String filename) {
        try {
            priKey.importEncryptedPrivateKeyInfoPem("1234", resourcePath + filename);
   //         Tools.printHex("私钥:",priKey.exportPrivateKeyInfoDer());
        } catch (GmSSLException e) {
            System.err.println("导入密钥失败: " + e.getMessage());
        }
        return priKey;
    }
    public   Sm2Key getPubKey() {

     //   Tools.printHex("公钥:",this.pubKey.exportPublicKeyInfoDer());
        return this.pubKey;
    }



    public   boolean  verifycert(String filename) {
        String resourcePath = System.getProperty("user.dir") + "/src/main/resources/";
        //参考链接：https://gmssl-docs.readthedocs.io/zh-cn/latest/multi_language/java.html#id1
        Sm2Certificate sm2Cert = new Sm2Certificate();
        Sm2Certificate subcaCert = new Sm2Certificate();
        Sm2Certificate rootcaCert = new Sm2Certificate();


        try {
            //todo 证书有效期读取失败

            //sm2Cert.importPem(resourcePath + "datareceivecert.pem");

            sm2Cert.importPem(resourcePath + filename);
//            Tools.printHex("证书number:", sm2Cert.getSerialNumber());
//
            System.out.println("证书起始日期："+sm2Cert.getNotBefore()+"\n证书结束日期："+sm2Cert.getNotAfter());
//            System.out.println("证书Issuer："+ Arrays.toString(sm2Cert.getIssuer()));
        } catch (Exception e) {
            System.out.println("导入证书失败: " + e.getMessage());
        }

        // todo  检查证书是否在有效期内,返回值有问题
        Date now = Date.from(Instant.now());
        if (now.before(sm2Cert.getNotBefore())) {
//            System.err.println("证书尚未生效");
//            return false;
        }
        if (now.after(sm2Cert.getNotAfter())) {
//            System.err.println("证书已过期");
//            return false;
        }
        //todo 根据签发机构（证书Issuer）自动选择证书
        //todo  检查证书是否作废主要是通过证书作废列表CRL文件检查，或者通过证书状态在线检查协议OCSP来在线查询。目前Sm2Certificate类没有支持证书作为查询的功能，开发者暂时可以通过GmSSL库或者gmssl命令行工具进行CRL的检查。


        //https://blog.csdn.net/fengshenyun/article/details/124596279
        //      System.out.println("证书subject:"+ Arrays.toString(sm2Cert.getSubject()));
        //ASN.1 ------（序列化）------ DER ------（Base64编码）------ PEM
        //    Tools.printHex("发送端公钥:", sm2Cert.getSubjectPublicKey().exportPublicKeyInfoDer());
        this.pubKey = sm2Cert.getSubjectPublicKey();
        //在完成所有证书检查之后，应用可以完全信任从证书中读取的持有者身份信息(subject)和支持有的公钥了，这两个信息分别通过getSubject和getSubjectPublicKey方法获得。

        subcaCert.importPem(resourcePath + "ca/subcacert.pem");
        if(sm2Cert.verifyByCaCertificate( subcaCert, Sm2Key.DEFAULT_ID) ){
           // System.out.println("证书有效");
            return true;
        }else
        {
            //System.err.println("证书无效");
            return false;
        }




    }

}
