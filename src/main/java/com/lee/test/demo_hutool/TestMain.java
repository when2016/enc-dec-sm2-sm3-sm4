package com.lee.test.demo_hutool;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.KeyUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import org.apache.commons.codec.binary.Base64;

import java.security.KeyPair;


//java tool hutool.jar
public class TestMain {

    public static void main(String[] args) {
        //sm2_01();
        //sm2_02();
        sm2_03();
        //sm4();
        //sm4_02();
    }

    //非对称加密（RSA）使用随机生成的密钥对加密或解密
    private static void sm2_01() {

        String text = "我是一段测试aaaa";
        System.out.println("text==" + text);
        SM2 sm2 = SmUtil.sm2();
        // 公钥加密，私钥解密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println("encryptStr==" + encryptStr);
        System.out.println("decryptStr==" + decryptStr);
    }

    //非对称加密（RSA）使用自定义密钥对加密或解密
    private static void sm2_02() {

        String text = "我是一段测试aaaa王红恩";
        System.out.println("text==" + text);

        String privateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgaffye0uSzuhFIe3VXVq/xSJFad4RqVJLJ9jdcH/3HN2gCgYIKoEcz1UBgi2hRANCAAT4S+86mtoBn9w0Y10qyQhXKm3h1K3mPp0b7UksL5JAG/xlQ/fIX2cA2alzTTA0Tm11Vw/V/Cvj5Qqmv8zsn9Vy";
        String publicKey = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE+EvvOpraAZ/cNGNdKskIVypt4dSt5j6dG+1JLC+SQBv8ZUP3yF9nANmpc00wNE5tdVcP1fwr4+UKpr/M7J/Vcg==";

        byte[] privateKeyAA = Base64.decodeBase64(privateKey);
        String privateKeyAATmp = Base64.encodeBase64String(privateKeyAA);
        System.out.println(privateKeyAATmp);

        SM2 sm2 = SmUtil.sm2(privateKey, publicKey);
        // 公钥加密，私钥解密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println("encryptStr==" + encryptStr);
        System.out.println("decryptStr==" + decryptStr);
    }

    //非对称加密（RSA）使用自定义密钥对加密或解密
    private static void sm2_03() {

        String text = "我是一段测试aaaa";
        System.out.println("text==" + text);

        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        byte[] privateKey = pair.getPrivate().getEncoded();
        byte[] publicKey = pair.getPublic().getEncoded();

        String base64_priKey=Base64.encodeBase64String(privateKey);
        String base64_pubKey=Base64.encodeBase64String(publicKey);
        System.out.println("base64_priKey===="+base64_priKey);
        System.out.println("base64_pubKey===="+base64_pubKey);

        SM2 sm2 = SmUtil.sm2(privateKey, publicKey);
        // 公钥加密，私钥解密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println("encryptStr==" + encryptStr);
        System.out.println("decryptStr==" + decryptStr);
    }

    //对称加密（AES）对称加密SM4
    private static void sm4_02() {

        String content = "test中文fffffffffffff中国人民解放军";


        //对称加密的key
        String sm4Key = "6o71sNhinsfaHFouUEehPA==";
        byte[] key = Base64.decodeBase64(sm4Key);

        System.out.println("content==" + content);
        SymmetricCrypto sm4 = SmUtil.sm4(key);


        String encryptHex = sm4.encryptHex(content);
        System.out.println("encryptHex==" + encryptHex);
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);

        System.out.println("decryptStr==" + decryptStr);
    }

    //对称加密（AES）对称加密SM4
    private static void sm4() {
        String content = "test中文";

        System.out.println("content==" + content);
        SymmetricCrypto sm4 = SmUtil.sm4();

        String encryptHex = sm4.encryptHex(content);
        System.out.println("encryptHex==" + encryptHex);
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);

        System.out.println("decryptStr==" + decryptStr);
    }
}
