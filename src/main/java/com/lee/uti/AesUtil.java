package com.lee.uti;

import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.krb5.internal.crypto.Aes128;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Random;

/**
 * AES加、解密算法工具类
 */
public class AesUtil {
    /**
     * 加密算法AES
     */
    private static final String KEY_ALGORITHM = "AES";

    /**
     * key的长度，Wrong key size: must be equal to 128, 192 or 256
     * 传入时需要16、24、36
     */
    private static final Integer KEY_LENGTH = 16 * 8;

    /**
     * 算法名称/加密模式/数据填充方式
     * 默认：AES/ECB/PKCS5Padding
     */
    private static final String ALGORITHMS = "AES/ECB/PKCS5Padding";

    /**
     * 后端AES的key，由静态代码块赋值
     */
    public static String key;

    /**
     * 不能在代码中创建
     * JceSecurity.getVerificationResult 会将其put进 private static final Map<Provider,Object>中，导致内存缓便被耗尽
     */
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    static {
        key = getKey();
    }

    /**
     * 获取key
     */
    public static String getKey() {
        StringBuilder uid = new StringBuilder();
        //产生16位的强随机数
        Random rd = new SecureRandom();
        for (int i = 0; i < KEY_LENGTH / 8; i++) {
            //产生0-2的3位随机数
            int type = rd.nextInt(3);
            switch (type) {
                case 0:
                    //0-9的随机数
                    uid.append(rd.nextInt(10));
                    break;
                case 1:
                    //ASCII在65-90之间为大写,获取大写随机
                    uid.append((char) (rd.nextInt(25) + 65));
                    break;
                case 2:
                    //ASCII在97-122之间为小写，获取小写随机
                    uid.append((char) (rd.nextInt(25) + 97));
                    break;
                default:
                    break;
            }
        }
        return uid.toString();
    }

    /**
     * 加密
     *
     * @param content    加密的字符串
     * @param encryptKey key值
     */
    public static String encrypt(String content, String encryptKey) throws Exception {
        //设置Cipher对象
        Cipher cipher = Cipher.getInstance(ALGORITHMS, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptKey.getBytes(), KEY_ALGORITHM));

        //调用doFinal
        // 转base64
        return Base64.encodeBase64String(cipher.doFinal(content.getBytes(StandardCharsets.UTF_8)));

    }

    /**
     * 解密
     *
     * @param encryptStr 解密的字符串
     * @param decryptKey 解密的key值
     */
    public static String decrypt(String encryptStr, String decryptKey) throws Exception {
        //base64格式的key字符串转byte
        byte[] decodeBase64 = Base64.decodeBase64(encryptStr);

        //设置Cipher对象
        Cipher cipher = Cipher.getInstance(ALGORITHMS,PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptKey.getBytes(), KEY_ALGORITHM));

        //调用doFinal解密
        return new String(cipher.doFinal(decodeBase64));
    }


    public static void main(String[] args) throws Exception {


        //String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCWKgzE53nM1ermqYgDD9T/KsKJuDH/xwJnL2mbSXQKRTBFLUeMjTbL5EAbqP1O8V9z8QYgYKjvMQhgOZNDGe0IjE3+Hy0hy7Fch5YELI+SlDMO0iBH8J9ndpCYvMD+4+aG5Fvra99MRwqYW6CZmQpUSIYRj4Flue7w9jf5fq5kFwIDAQAB";
        //String key = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJYqDMTneczV6uapiAMP1P8qwom4Mf/HAmcvaZtJdApFMEUtR4yNNsvkQBuo/U7xX3PxBiBgqO8xCGA5k0MZ7QiMTf4fLSHLsVyHlgQsj5KUMw7SIEfwn2d2kJi8wP7j5obkW+tr30xHCphboJmZClRIhhGPgWW57vD2N/l+rmQXAgMBAAECgYBudoxiJK1yw0JDYB7PscvL0Va+HKObNnhME5KqSwRzsaXqnX5upErU/hkyv8NnWSQQlBMfqjtbiURSFMiBqga1DI3lw7uggGCE+PlvLRqWDjxHRsobLq0152ChYHpOF0vCv9xnSlTnu2qQ/qmtEB4mOCay86yyJsFCqDwnnGmGAQJBAMe776kXF5OMWyhTIP+Q7XjW3ycZ03Aus1dxnRtnVHkgSgvprbx6bVUJEUJaZ17fRmU7bqu1/Yq4CSIba5A14IECQQDAd1Lg6v63tYHeX1EftcjBKTOBxN1naAYYheY5hKnzsNktSPGIzJZi6xs2USA3aT6PA+6GYZEji8ZVymBIaviXAkB4KO02majaYE8bBF/OwF7NGt+nQ1c7nyzPh49PxCtCr5U8c3nM8Q5DYTAb7g1QOxy7nDSpYtRElxEPjtV4LaGBAkB2Y6/WbJbceEj3eZhUMiTYNLjbNTaf2gwN36ebb/B+1yTwRzNT280R8d7eTY7Mpu91V4zMmo2F2P/aW89YHHznAkEAhy3+a2Lu9F/a0I5DhitkZXSCiwhjNfR3+/vwLEiP5ti7Ya/CLxqZONbH6Y0t6xUiXpKc+6i4xXkqBgsdemPSRw==";


        String data = "中国";
        String key = AesUtil.getKey();
        System.out.println("---加密");
        System.out.println("encKey=="+key);
        String encData = AesUtil.encrypt(data,key);
        System.out.println("encData="+encData);

        System.out.println("---解密-------");
        String decData = AesUtil.decrypt(encData,key);
        System.out.println("decData=="+decData);


    }

}
