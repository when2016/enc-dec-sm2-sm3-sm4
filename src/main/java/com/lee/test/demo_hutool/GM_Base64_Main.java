package com.lee.test.demo_hutool;

import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import com.lee.uti.HexConvertUtil;

import java.security.KeyPair;

public class GM_Base64_Main {

    private static final String publicKey = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE+EvvOpraAZ/cNGNdKskIVypt4dSt5j6dG+1JLC+SQBv8ZUP3yF9nANmpc00wNE5tdVcP1fwr4+UKpr/M7J/Vcg==";
    private static final String privateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgaffye0uSzuhFIe3VXVq/xSJFad4RqVJLJ9jdcH/3HN2gCgYIKoEcz1UBgi2hRANCAAT4S+86mtoBn9w0Y10qyQhXKm3h1K3mPp0b7UksL5JAG/xlQ/fIX2cA2alzTTA0Tm11Vw/V/Cvj5Qqmv8zsn9Vy";

    public static void main(String[] args) {
        String text = "我是一段测试aaaa王红恩";
        sm2_03(text);

    }

    //非对称加密（RSA）使用自定义密钥对加密或解密
    private static void sm2_02(String text) {

        System.out.println("publicKey====" + publicKey);
        System.out.println("privateKey====" + privateKey);
        System.out.println("text==" + text);
        SM2 sm2 = SmUtil.sm2(privateKey, publicKey);
        // 公钥加密，私钥解密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println("encryptStr==" + encryptStr);
        System.out.println("decryptStr==" + decryptStr);
    }

    //非对称加密（RSA）使用自定义密钥对加密或解密
    private static void sm2_03(String text) {
        System.out.println("text==" + text);

        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        byte[] privateKey = pair.getPrivate().getEncoded();
        byte[] publicKey = pair.getPublic().getEncoded();

        String priKey16 = HexConvertUtil.bytes2hexStr(privateKey);
        String pubKey16 = HexConvertUtil.bytes2hexStr(publicKey);
        System.out.println("priKey16===" + priKey16.toUpperCase());
        System.out.println("pubKey16===" + pubKey16.toUpperCase());



        SM2 sm2 = SmUtil.sm2(privateKey, publicKey);

        // 公钥加密，私钥解密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println("encryptStr==" + encryptStr);
        System.out.println("decryptStr==" + decryptStr);
    }


}
