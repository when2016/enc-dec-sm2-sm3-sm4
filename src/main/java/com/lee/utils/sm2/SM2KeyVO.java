package com.lee.utils.sm2;

import com.lee.utils.ConverterUtil;
import com.lee.utils.SM234Util;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class SM2KeyVO {
    BigInteger privateKey;
    ECPoint publicKey;

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(ECPoint publicKey) {
        this.publicKey = publicKey;
    }


    //HardPubKey:3059301306072A8648CE3D020106082A811CCF5501822D03420004+X+Y
    //SoftPubKey:04+X+Y
    public String getPubHexInSoft() {
        return ConverterUtil.byteToHex(publicKey.getEncoded());
        //System.out.println("公钥: " + );
    }

    public String getPubHexInHard() {
        return SM234Util.SM2PubHardKeyHead + ConverterUtil.byteToHex(publicKey.getEncoded());
    }

    public String getPriHexInSoft() {
        return ConverterUtil.byteToHex(privateKey.toByteArray());
    }
}
