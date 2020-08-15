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
 *  AES + RSA 加解密环绕处理
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
                String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAITrr77YBkhmFu/BZw35iqk1vy9fpH6Gn0eIz+PAmNgYgLS1Bu5Z156HgVQeEqXLrlvErTKwBLMfau+5GdZRE9dz2sJmpNsPuA9hYr8VpONG02S7ReWDgF5a86yggY2RYpnGs4ft8pxobgVm296QPJUg04zruHXIAzW9fr9yefuzAgMBAAECgYEAgNaCjxWNYXezG8n3PhB3WvSB0EWAiDOtCAWQnE3+2NdHSeF+SmJDIaJutT5BDPuUkdbdmpgKtiTp3lsotBf6hhYZs5kGsWWH8u+eUaDRGbhxpuTtJlPotFgp0Oer+q7w5ZNuyVgI6uPq1+6iqfy4hsO0WvpaavVexU5w25WvVSECQQDvnPB8cAc3j7Xjj+lg+k3hDdpMPd5K0dbWZT/ELxY/zJm7RPzserclS+2jBOSnD8KhPt8pvs+o1XFLVOaCkhDdAkEAjgLQeB3c72GGYxucb2ugC+wBZ3yw3OYkWEALx9inmiSs3VwVJE94oH4bFGmh6jJWW69xbRkslCNDNTi3yM2tzwJBAKOKH/EunR5k7aXlgUn5TNJAHDBRQbkbQ2CNNlp2MN9Wi85vJZlZoErKaeUL3+vOK+7V9IaPfzgihfL+fV28x9kCQFR0SgRVRjI6npBMOGFu8RSF+2PPHOOSHqU5GYh1SV97Vi6i95PLi2Ju/K3MEFXWL9OA6ATIxuEmg26gV3QdFbMCQEAInhegRkbYgGTc3N5XNDSvJDlVVwKK0rrfcUcrx13DoOJIJZlQWkPKZnqB3EZLFUhUWwFQVefNkeGox9gI5do=";


                //后端私钥解密的到AES的key
                byte[] plaintext = RsaUtil.decryptByPrivateKey(Base64.decodeBase64(aesKey), privateKey);
                aesKey = new String(plaintext);
                log.info("解密出来的AES的key：" + aesKey);

                //RSA解密出来字符串多一对双引号d
                aesKey = aesKey.substring(1, aesKey.length() - 1);

                //AES解密得到明文data数据
                String decrypt = AesUtil.decrypt(data, aesKey);

                log.info("解密出来的data数据：" + decrypt);

                if (args.length > 0) {
                    args[0] = JSONObject.parseObject(decrypt,args[0].getClass());
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
                AesUtil.decrypt(data,key);
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
