package com.lee.aspect;

import com.alibaba.fastjson.JSONObject;
import com.lee.ResponseVO;
import com.lee.annotation.Decrypt;
import com.lee.annotation.Encrypt;
import com.lee.uti.AesUtil;
import com.lee.uti.RsaUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * AES + RSA 加解密环绕处理
 *
 * @param:
 * @return:
 * @auther: liyiyu
 * @date: 2020/6/27 23:29
 */
@Slf4j
@Aspect
@Component
public class SafetyAspect {

    /**
     * Pointcut 切入点
     * 匹配
     */
    @Pointcut(value = "execution(public * com.lee.controller.*.*(..))")
    public void safetyAspect() {
    }

    @Around(value = "safetyAspect()")
    public Object around(ProceedingJoinPoint pjp) {
        try {

            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            assert attributes != null;
            //request对象
            HttpServletRequest request = attributes.getRequest();

            //http请求方法  post get
            String httpMethod = request.getMethod().toLowerCase();

            //method方法
            Method method = ((MethodSignature) pjp.getSignature()).getMethod();

            //method方法上面的注解
            Annotation[] annotations = method.getAnnotations();

            //方法的形参参数
            Object[] args = pjp.getArgs();

            //是否有@Decrypt
            boolean hasDecrypt = false;
            //是否有@Encrypt
            boolean hasEncrypt = false;
            for (Annotation annotation : annotations) {
                if (annotation.annotationType() == Decrypt.class) {
                    hasDecrypt = true;
                }
                if (annotation.annotationType() == Encrypt.class) {
                    hasEncrypt = true;
                }
            }


            //执行方法之前解密，且只拦截post请求
            if ("post".equals(httpMethod) && hasDecrypt) {

                BufferedReader br = new BufferedReader(new InputStreamReader(request.getInputStream(), "UTF-8"));
                String line;
                StringBuilder sb = new StringBuilder();
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
                br.close();
                JSONObject jsonObject = JSONObject.parseObject(sb.toString());


                //AES加密后的数据
                String data = jsonObject.getString("data");
                //后端RSA公钥加密后的AES的key
                String aesKey = jsonObject.getString("aesKey");
                //前端私钥
                String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKV8FG7Vi6/X4eqyPg4DTDRGvZnK/m51qP626KHltCDmW/qXvBr+6yMMDn3XMTnAvhGBvqLzZUeIbF7bxTx17WCHDZCReq8z5qnRqNJ6wPM1B3baIi4xgKVwRwyMsb/QhqNv4LYqg3Tw2fcN8JJLzM2EPr5S93Sq8kdblNbsgLjRAgMBAAECgYBEVpE5lAYzf7tT6Hen4cS+cdgqgqG/i+dWCMLY2LsiOv8Q5UhQ/aSsvHXfkdZKO0ZChIntUQYqHDRkl+1Doo97+UYUyZnA2zUiGXY6eKMEGFUDpZQgw3beSJ2wemeKM4ZBeuU8NBPER+6a/B54skRPC+1LSnqhVXIc1ti4wLFWAQJBAPARk78o9wxfF3g9r+BH/itFSV/liaEjMU9LdyXlE57KOQu2Wg7QKIYN2PUTPSCuHynpn1S//vsOCAQcU+LgWVkCQQCwd22AOnb0F1/29yrwKFI8JVi81K8803x1KyvWao66jCo1ylcGloohhOHWCDGFDA2fTgPniNjkmks2k4feBPQ5AkEAlQW0O1PIl6tnvEI+rPDDvESUWaz5FEfuUhS8b4+V8FoDs1uM5+kbXqu149v/dAviWHgnacqNE3cQTszu3cT6cQJAEvH/c5DTTIll6CHJHld13Lc1u7Ap0CH0bq/f2Pk/sY9yyKuchDyNP+QASvY+OsZ8f+nkSWtLvd9Cy+0y3QczIQJBAIcbdktp5Ooka9mYNEDphLhTNXet+fyQobnAFJW9iuzdmpEHCEyWUKyU4fqtheYbz4o5AJb+ly9H3mYCVp0FXtw=";


                //后端私钥解密的到AES的key
                byte[] plaintext = RsaUtil.decryptByPrivateKey(Base64.decodeBase64(aesKey), privateKey);
                aesKey = new String(plaintext);
                log.info("解密出来的AES的key：" + aesKey);

                //RSA解密出来字符串多一对双引号d
                aesKey = aesKey.substring(1, aesKey.length() - 1);
                log.info("解密出来的AES的(RSA解密出来字符串多一对双引号)key：" + aesKey);

                //AES解密得到明文data数据
                String decrypt = AesUtil.decrypt(data, aesKey);

                log.info("解密出来的data数据：" + decrypt);

                if (args.length > 0) {
                    args[0] = JSONObject.parseObject(decrypt, args[0].getClass());
                }
            }

            //执行目标方法
            //PS：这里有一个需要注意的地方，方法必须public修饰
            Object obj = pjp.proceed(args);

            //返回结果之前加密
            if (hasEncrypt) {
                ResponseVO responseVO = (ResponseVO) obj;
                //后端公钥
                String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDsDQmZ1QbQOAAzxQvnyTpx77M11pCmXy/5Sqhsyupur0MZ75vFu71x5FBY0XJSbzsUgfEzqRjlFh1dKx0ViMicUa2ZQ2w/yHRemub6QYmpKHKk5sUvRC+fYNWWnjKTnkAuMefr6Ry98dOgVYrpmUkKGfv5UJz33yl2Kd2WYbnLRwIDAQAB";
                //每次响应之前随机获取AES的key，加密data数据
                String key = AesUtil.getKey();
                log.info("AES的key：" + key);
                log.info("需要加密的data数据：" + obj);
                String data = AesUtil.encrypt(JSONObject.toJSONString(responseVO.getBody()), key);
                AesUtil.decrypt(data, key);
                //用前端的公钥来解密AES的key，并转成Base64
                String aesKey = Base64.encodeBase64String(RsaUtil.encryptByPublicKey(key.getBytes(), publicKey));

                //转json字符串并转成Object对象，设置到Result中并赋值给返回值o
                Map<String, Object> map = new HashMap<>();
                map.put("data", data);
                map.put("aesKey", aesKey);
                responseVO.setBody(map);
                obj = responseVO;
            }
            return obj;
        } catch (Throwable e) {
            //输出到日志文件中
            log.error("加解密异常：" + e.getMessage());
            return "加解密异常";
        }
    }


}
