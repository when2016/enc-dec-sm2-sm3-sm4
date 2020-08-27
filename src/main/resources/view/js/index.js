var aesUtil = {

    //获取key，
    genKey: function (length = 16) {
        let random = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let str = "";
        for (let i = 0; i < length; i++) {
            str = str + random.charAt(Math.random() * random.length)
        }
        return str;
    },

    //加密
    encrypt: function (plaintext, key) {
        if (plaintext instanceof Object) {
            //JSON.stringify
            plaintext = JSON.stringify(plaintext)
        }
        let encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(plaintext), CryptoJS.enc.Utf8.parse(key), {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        });
        return encrypted.toString();
    },

    //解密
    decrypt: function (ciphertext, key) {
        let decrypt = CryptoJS.AES.decrypt(ciphertext, CryptoJS.enc.Utf8.parse(key), {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        });
        let decString = CryptoJS.enc.Utf8.stringify(decrypt).toString();
        if (decString.charAt(0) === "{" || decString.charAt(0) === "[") {
            //JSON.parse
            decString = JSON.parse(decString);
        }
        return decString;
    }
};


var rsaUtil = {
    //RSA 位数，这里要跟后端对应
    bits: 1024,

    //当前JSEncrypted对象
    thisKeyPair: new JSEncrypt({default_key_size: 1024}),

    //生成密钥对(公钥和私钥)
    genKeyPair: function (bits = rsaUtil.bits) {
        let genKeyPair = {};
        rsaUtil.thisKeyPair = new JSEncrypt({default_key_size: bits});

        //获取私钥
        genKeyPair.privateKey = rsaUtil.thisKeyPair.getPrivateKey();

        //获取公钥
        genKeyPair.publicKey = rsaUtil.thisKeyPair.getPublicKey();

        return genKeyPair;
    },

    //公钥加密
    encrypt: function (plaintext, publicKey) {
        if (plaintext instanceof Object) {
            //1、JSON.stringify
            plaintext = JSON.stringify(plaintext)
        }
        publicKey && rsaUtil.thisKeyPair.setPublicKey(publicKey);
        return rsaUtil.thisKeyPair.encrypt(JSON.stringify(plaintext));
    },

    //私钥解密
    decrypt: function (ciphertext, privateKey) {
        privateKey && rsaUtil.thisKeyPair.setPrivateKey(privateKey);
        let decString = rsaUtil.thisKeyPair.decrypt(ciphertext);
        if (decString.charAt(0) === "{" || decString.charAt(0) === "[") {
            //JSON.parse
            decString = JSON.parse(decString);
        }
        return decString;
    }
};


function subimt() {
    var data = {
        "username": $("#username").val(),
        "password": $("#password").val()
    };
    $("#myh1").html("前端端传输真实内容:" + JSON.stringify(data));
    var aesKey = aesUtil.genKey();
    data = aesUtil.encrypt(data, aesKey);
    //前端RSA公钥
    var publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClfBRu1Yuv1+Hqsj4OA0w0Rr2Zyv5udaj+tuih5bQg5lv6l7wa/usjDA591zE5wL4Rgb6i82VHiGxe28U8de1ghw2QkXqvM+ap0ajSesDzNQd22iIuMYClcEcMjLG/0Iajb+C2KoN08Nn3DfCSS8zNhD6+Uvd0qvJHW5TW7IC40QIDAQAB";
    aesKey = rsaUtil.encrypt(aesKey, publicKey);
    //发送请求之前随机获取AES的key
    data = {
        data: data,//AES加密后的数据
        aesKey: aesKey,//后端RSA公钥加密后的AES的key
        publicKey: window.jsPublicKey//前端公钥
    };
    $("#myh2").html("前端端传输内容(加密后):" + JSON.stringify(data));
    $.ajax({
        url:'login',  //发送的地址
        type:'POST',  //请求的方式
        data:JSON.stringify(data),//要传入的数据
        contentType:'application/json', //返回的数据类型
        success:function(res){
            var data = res.body.data;
            var aesKey = res.body.aesKey;
            var privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAOwNCZnVBtA4ADPFC+fJOnHvszXWkKZfL/lKqGzK6m6vQxnvm8W7vXHkUFjRclJvOxSB8TOpGOUWHV0rHRWIyJxRrZlDbD/IdF6a5vpBiakocqTmxS9EL59g1ZaeMpOeQC4x5+vpHL3x06BViumZSQoZ+/lQnPffKXYp3ZZhuctHAgMBAAECgYBIK1BFJRlZLdX5/gO+0Qo6bYPIMRq2kyGywT2vTXbRcmo8ksJ4eQbZvGlITnj6dSGGCph5J/kBiXpe0uCohdJ3SizbLpJ2l88KZ6LYvtQ1o8szEHqxyifeoEEWb2Yi2wwYsbdyw24JHct7oIXWrBiNWtKtPsC4HUdHuBIt4HXLiQJBAPz5+c5iroW4tTDRU61J+j36R6QVDwe6p7gVjp5GKklDphnjDntQ2la/NLoD9auOF7naoZzxd7wTY8q5pBP1ipsCQQDu30ZwU9JQf3TyLNkC9N8liZAnIeil6thN7TZibAS9x19aNiZotsnP/ecq7FFqBA9mC5iqBjOek9eiW7DAu4bFAkEA+wzgeY64/3+UYMP7tIcrzgHows8bQWJdO3Q5Op0LLfXyitIn9v0AEQJjww5W6U90AD8WD3gaiQz9BZxBVoVgbQJBAKkgyTzK/IQmWmUFv/lJ650mUzyB07l2GATEydbR6GF+glLbOEK3+RgdC8nmXJaVnVmBKGxpy66huvGnvfQYUokCQQD2CDFuzS/fX1N57EPUHB1HS1UgXwlQlXcWPSq5Jw6r1VkIIe7iEYh+w5V07Lb1uw5HebuErKAqrus+lUr282mF";
            var str = rsaUtil.decrypt(aesKey, privateKey);
            var responseData = aesUtil.decrypt(data, str);
            $("#myh3").html("后端返回内容:" + JSON.stringify(res));
            $("#myh4").html("后端返回内容解密后:" + JSON.stringify(responseData));
        }
    });

}