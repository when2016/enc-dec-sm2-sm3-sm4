package com.lee.test.demo_hex;

import com.lee.utils.ConverterUtil;
import com.lee.utils.SM234Util;
import com.lee.utils.sm2.SM2KeyVO;

public class TestHexMain {


    public static void main(String[] args) throws Exception {
        //16进制
        String publicKey = "049975A7BA7FC6BDBCD32A638F5D90047E011D61758A1C061C6999812A9C0597753B7B02FB9178B364DCC346EC995B7AE6C8E5BAD8C44505FF17BFF79A6655F632";
        String privateKey = "0891CD3D5B775EFBCAF6E516721CB0E8ECE086032C94AB335E121DE6847323B1";

        //随机生成密钥对（公钥、私钥），对内容做加解密
        sm2_00_enc_dec("我是一段测试aaaa王红恩");

        //使用指定的密钥对（公钥、私钥），对内容做加解密
        sm2_01_enc_dec(publicKey, privateKey, "我是一段测试aaaa王红恩");




    }

    /**
     * 随机生成密钥对（公钥、私钥），对内容做加解密
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
     * 使用指定的密钥对（公钥、私钥），对内容做加解密
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
}
