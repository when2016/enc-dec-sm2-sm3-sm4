
###  20200828
###  java sm2&sm4 use hutool.jar















### 开发背景

最近公司项目的小程序出现黑客利用抓包工具解析参数并恶意调用接口的情况。虽然我们的服务器安装了HTTPS证书，但是由于小程序的局限性，无法做到客户端对服务端请求的加密。别有用心的人安装抓包工具后可以轻易抓到与我们服务器的请求和返回数据。在研究了HTTPS的原理后，在前后端数据传输前，再次将数据加密一次。

### 设计思路

端对端的加/解密过程类似于HTTPS加密，执行加解密过程如下图

**为什么使用混合加密？**

非对称加解密算法在加解密大对象的时候性能较差，而对称性加解密性能较好，所以用对称性加密算法加密真实数据，非对称性算法加密对称性秘钥。

确定思路后，就开始找RSA和AES加解密的工具类。因为我这边对小程序代码不熟悉，所以利用thymeleaf模板进行模拟小程序端。



### 开发思路

1.加/解密过程肯定会带来性能损耗，所以只需要在关键的接口/返回数据进行处理

2.加/解密对原来代码无侵入性，加入功能后原先接口的入参和返回参数不需要修改。所以选用**AOP环绕和自定义注解（@Decrypt，@Encrypt）**来实现，解密的时候利用反射获取接口入参对应的类，获取到request流里的数据并解密后生成类对象再进行传递。加密的时候获取返回对象，进行加密再传递

3.A->B加/解密和B->A加解密 是两端独立的过程，所以需要配置两套RSA秘钥

**这里附上环绕的实现过程**

```java
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
                String privateKey = "";


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
                String publicKey = "";
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
```

**在需要加/解密的控制层方法上加上注解**

因为我们本身数据是封装在一个返回类里，因为范式检查只在编译阶段进行，加密后返回的数据实际上是HashMap也不会报错。如果其他返回数据是直接返回类型的话需要将返回参数修改成Object类

```java
		@Decrypt //获取数据前解密
    @Encrypt //返回数据后加密
    @PostMapping("/login")
    public ResponseVO<User> login(LoginDTO loginDTO){
        if ("lee".equals(loginDTO.getUsername()) && "123".equals(loginDTO.getPassword())){
            User user = User.builder()
                    .name("lee")
                    .sex(1)
                    .age(18)
                    .build();

            return ResponseVO.success(user);
        }else {
            User user = User.builder().build();
            return ResponseVO.fail(user);
        }

    }
```



### 注意事项

1.网络安全没有绝对的安全，简单二次加密只能拦截掉大部分的新手黑客，加大解析的难度。

2.两端的秘钥不能被第三方获取，服务端的秘钥存储在服务器配置文件上，小程序端的秘钥也是存储在支付宝/微信端小程序服务器中。咨询过支付宝客服，他们说正常情况下小程序代码不会被第三方获取（只能信任于他们了。。。）

3.参考文章
 * https://github.com/leeyiyu/EncryptionAndDecryption
 * https://blog.csdn.net/liyiyu123/article/details/108023058
 * https://blog.csdn.net/weixin_34009794/article/details/88023046
 * https://www.jianshu.com/p/c7ea4d1a8b3b?from=singlemessage


