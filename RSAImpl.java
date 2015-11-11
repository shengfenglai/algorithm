package com.lsf.main;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Hex;

public class RSAImpl {
    
    private static final String MYSECURITY = "HELLOWORLD";

    public static void main(String[] args) {
        rsaWithJDKImpl();
    }
    
    
    public static void rsaWithJDKImpl(){
        try {
            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();  
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            //2.执行签名
            PKCS8EncodedKeySpec  pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initSign(privateKey);
            signature.update(MYSECURITY.getBytes());
            byte[] result = signature.sign();
            System.out.println("jdk rsa sign:" + Hex.encodeHexString(result));//把内容转成16进制
            
            //3.验证签名
            X509EncodedKeySpec X509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(X509EncodedKeySpec);
            signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);
            signature.update(MYSECURITY.getBytes());
            boolean flag = signature.verify(result);
            System.out.println("jdk rsa verify:" + flag);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
