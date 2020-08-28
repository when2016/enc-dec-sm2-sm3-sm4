package com.lee.utils;

import com.lee.utils.sm2.SM2EncDecUtils;
import com.lee.utils.sm2.SM2KeyVO;

import java.io.IOException;

public class SM234Util {
    public static final String SM2PubHardKeyHead = "3059301306072A8648CE3D020106082A811CCF5501822D034200";

    //产生非对称秘钥
    public static SM2KeyVO generateSM2Key() throws IOException {
        SM2KeyVO sm2KeyVO = SM2EncDecUtils.generateKeyPair();
        return sm2KeyVO;
    }

    //公钥加密
    public static String SM2Enc(String pubKey, String src) throws IOException {
        String encrypt = SM2EncDecUtils.encrypt(ConverterUtil.hexStringToBytes(pubKey), src.getBytes());
        //删除04
        encrypt=encrypt.substring(2,encrypt.length());
        return encrypt;
    }

    //私钥解密
    public static String SM2Dec(String priKey, String encryptedData) throws IOException {
        //填充04
        encryptedData="04"+encryptedData;
        byte[] decrypt = SM2EncDecUtils.decrypt(ConverterUtil.hexStringToBytes(priKey), ConverterUtil.hexStringToBytes(encryptedData));
        return new String(decrypt);
    }

}
