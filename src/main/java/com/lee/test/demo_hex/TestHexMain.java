package com.lee.test.demo_hex;

import com.lee.utils.ConverterUtil;
import com.lee.utils.SM234Util;
import com.lee.utils.sm2.SM2KeyVO;
import com.lee.utils.sm2.SM2SignVO;

public class TestHexMain {


    public static void main(String[] args) throws Exception {
        //16进制
        String publicKey = "049975A7BA7FC6BDBCD32A638F5D90047E011D61758A1C061C6999812A9C0597753B7B02FB9178B364DCC346EC995B7AE6C8E5BAD8C44505FF17BFF79A6655F632";
        String privateKey = "0891CD3D5B775EFBCAF6E516721CB0E8ECE086032C94AB335E121DE6847323B1";

        String text = "我是一段测试aaaa王红恩";

        //sm2非对称加密----随机生成密钥对（公钥、私钥），对内容做加解密
        //sm2_00_enc_dec(text);

        //sm2非对称加密----使用指定的密钥对（公钥、私钥），对内容做加解密
        //sm2_01_enc_dec(publicKey, privateKey, text);

        //sm2签名
        sm2_sign(text);

        //sm4对称加密----
        //sm4_00_enc_dec("我是一段测试aaaa王红恩");


    }

    /**
     * sm2非对称加密
     * 随机生成密钥对（公钥、私钥），对内容做加解密
     *
     * @param text
     * @throws Exception
     */
    public static void sm2_00_enc_dec(String text) throws Exception {

        System.out.println("--产生SM2秘钥--:");
        SM2KeyVO sm2KeyVO = SM234Util.generateSM2Key();
        System.out.println("公钥:" + sm2KeyVO.getPubHexInSoft());
        System.out.println("私钥:" + sm2KeyVO.getPriHexInSoft());

        //数据加密
        System.out.println("--测试加密开始--");
        String src = "I Love You";
        System.out.println("原文UTF-8转hex:" + ConverterUtil.byteToHex(src.getBytes()));
        String SM2Enc = SM234Util.SM2Enc(sm2KeyVO.getPubHexInSoft(), src);
        System.out.println("加密:");
        System.out.println("密文:" + SM2Enc);
        String SM2Dec = SM234Util.SM2Dec(sm2KeyVO.getPriHexInSoft(), SM2Enc);
        System.out.println("解密:" + SM2Dec);
        System.out.println("--测试加密结束--");

    }

    /**
     * sm2非对称加密
     * 使用指定的密钥对（公钥、私钥），对内容做加解密
     *
     * @param publicKey
     * @param privateKey
     * @param text
     * @throws Exception
     */
    public static void sm2_01_enc_dec(String publicKey, String privateKey, String text) throws Exception {

        System.out.println("要加密的内容====" + text);

        System.out.println("--测试加密开始--");
        String src = text;
        System.out.println("原文UTF-8转hex:" + ConverterUtil.byteToHex(src.getBytes()));
        String SM2Enc = SM234Util.SM2Enc(publicKey, src);
        System.out.println("加密:");
        System.out.println("密文:" + SM2Enc);
        String SM2Dec = SM234Util.SM2Dec(privateKey, SM2Enc);
        System.out.println("解密:" + SM2Dec);
        System.out.println("--测试加密结束--");
    }

    /**
     * SM2签名
     *
     * @param text
     * @throws Exception
     */
    public static void sm2_sign(String text) throws Exception {
        String src = text;
        System.out.println("--测试SM2签名--");
        System.out.println("原文hex:" + ConverterUtil.byteToHex(src.getBytes()));
        String s5 = ConverterUtil.byteToHex(src.getBytes());

        System.out.println("--产生SM2秘钥--:");
        SM2KeyVO sm2KeyVO = SM234Util.generateSM2Key();
        System.out.println("公钥:" + sm2KeyVO.getPubHexInSoft());
        System.out.println("私钥:" + sm2KeyVO.getPriHexInSoft());

        System.out.println("签名测试开始:");
        SM2SignVO sign = SM234Util.genSM2Signature(sm2KeyVO.getPriHexInSoft(), s5);
        System.out.println("软加密签名结果:" + sign.getSm2_signForSoft());
        System.out.println("加密机签名结果:" + sign.getSm2_signForHard());
        //System.out.println("转签名测试:"+SM2SignHardToSoft(sign.getSm2_signForHard()));
        System.out.println("验签1,软件加密方式:");
        boolean b = SM234Util.verifySM2Signature(sm2KeyVO.getPubHexInSoft(), s5, sign.getSm2_signForSoft());
        System.out.println("软件加密方式验签结果:" + b);
        System.out.println("验签2,硬件加密方式:");
        String sm2_signForHard = sign.getSm2_signForHard();
        System.out.println("签名R:" + sign.sign_r);
        System.out.println("签名S:" + sign.sign_s);
        //System.out.println("硬:"+sm2_signForHard);
        b = SM234Util.verifySM2Signature(sm2KeyVO.getPubHexInSoft(), s5, SM234Util.SM2SignHardToSoft(sign.getSm2_signForHard()));
        System.out.println("硬件加密方式验签结果:" + b);
        if (!b) {
            throw new RuntimeException();
        }
        System.out.println("--签名测试结束--");
    }

    /**
     * sm3摘要加密hash
     *
     * @param text
     */
    public static void sm3(String text) {
        String src = text;
        System.out.println("--SM3摘要测试--");
        String s = SM234Util.generateSM3HASH(src);
        System.out.println("hash:" + s);
        System.out.println("--SM3摘要结束--");

    }

    /**
     * sm4对称加密
     * 随机生成密钥对（公钥、私钥），对内容做加解密
     *
     * @param text
     * @throws Exception
     */
    public static void sm4_00_enc_dec(String text) throws Exception {

        String src = text;

        System.out.println("--生成SM4秘钥--");
        String sm4Key = SM234Util.generateSM4Key();

        System.out.println("sm4Key:" + sm4Key);
        System.out.println("--生成SM4结束--");
        System.out.println("--SM4的CBC加密--");
        String s1 = SM234Util.SM4EncForCBC(sm4Key, src);
        System.out.println("密文:" + s1);
        System.out.println("CBC解密");
        String s2 = SM234Util.SM4DecForCBC(sm4Key, s1);
        System.out.println("解密结果:" + s2);

        System.out.println("--ECB加密--");
        String s3 = SM234Util.SM4EncForECB(sm4Key, src);
        System.out.println("ECB密文:" + s3);
        System.out.println("ECB解密");
        String s4 = SM234Util.SM4DecForECB(sm4Key, s3);
        System.out.println("ECB解密结果:" + s4);
    }
}
