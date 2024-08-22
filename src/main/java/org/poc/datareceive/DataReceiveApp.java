package org.poc.datareceive;
import org.gmssl.Random;
import org.gmssl.Sm2Key;
import org.gmssl.Sm4Ctr;
import org.poc.common.PrasePEM;

public class DataReceiveApp {


    public Sm2Key priKey;
    public Sm2Key pubKey;
    public DataReceiveApp() {
        PrasePEM sm = new PrasePEM("datareceivecert.pem");
        this.priKey = sm.getPriKey("datareceivekey.pem");
        this.pubKey = sm.getPubKey();

    }

    public String decData(byte[] ciphertext, byte[] sessionKey,int cipherlen) {
        Sm4Ctr sm4ctr = new Sm4Ctr();
        int plainlen;
        byte[] plaintext = new byte[64];
        byte[] iv= new byte[16];

        sm4ctr.init(sessionKey, iv);
        plainlen = sm4ctr.update(ciphertext, 0, 0, plaintext, 0);
        plainlen += sm4ctr.doFinal(plaintext, plainlen);

        return  new String(plaintext, 0, plainlen);
    }
}
