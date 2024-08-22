package org.poc.datasend;

import org.gmssl.*;

import org.jetbrains.annotations.NotNull;
import org.poc.common.PrasePEM;


public class DataSendApp {


    public Sm2Key priKey;
    public Sm2Key pubKey;
    public byte[] sessionKey;



    public DataSendApp() {
        PrasePEM sm = new PrasePEM("datasendcert.pem");
        this.priKey = sm.getPriKey("datasendkey.pem");
        this.pubKey = sm.getPubKey();
        Random rng = new Random();
        this.sessionKey =  rng.randBytes(Sm4Ctr.KEY_SIZE);


    }

    public Object[]  encData(String orgData){
        int cipherlen;

        // byte[] iv = rng.randBytes(Sm4Ctr.IV_SIZE);
        byte[] iv= new byte[16];
        byte[] ciphertext = new byte[64];
        Sm4Ctr sm4ctr = new Sm4Ctr();
        sm4ctr.init(sessionKey,iv);
        cipherlen = sm4ctr.update(orgData.getBytes(), 0, orgData.length(), ciphertext, 0);
        cipherlen += sm4ctr.doFinal(ciphertext, cipherlen);
        return  new Object[]{ciphertext, cipherlen};
    }



    public byte[] signData(@NotNull String orgData) {

        byte[] ciphertext = this.pubKey.encrypt(orgData.getBytes());
        byte[] plaintext = this.pubKey.decrypt(ciphertext);
        String  decData = new String(plaintext);
        System.out.printf("Ciphertext : "+decData);
        System.out.printf("Plaintext : ");
        int i;
        for (i = 0; i < plaintext.length; i++) {
            System.out.printf("%02x", plaintext[i]);
        }
        System.out.print("\n");

        Sm2Signature sign = new Sm2Signature(priKey, Sm2Key.DEFAULT_ID, true);

        sign.update(orgData.getBytes());
        byte[]  sig = sign.sign();

        Sm2Signature verify = new Sm2Signature(pubKey, Sm2Key.DEFAULT_ID, false);
        verify.update(orgData.getBytes());
        boolean verify_ret = verify.verify(sig);
        System.out.println("Verify result = " + verify_ret);
        return  ciphertext;
    }

}












