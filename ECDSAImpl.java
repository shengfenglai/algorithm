package com.lsf.main;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Hex;

public class ECDSAImpl {
    
    private static final String MYSECURITY = "HELLOWORLD";

    public static void main(String[] args) {
        ecdsaWithJDKImpl();
    }
    
    
    public static void ecdsaWithJDKImpl(){
        try {
            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();  
            ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
            //2.执行签名
            PKCS8EncodedKeySpec  pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(ecPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA1withECDSA");
            signature.initSign(privateKey);
            signature.update(MYSECURITY.getBytes());
            byte[] result = signature.sign();
            System.out.println("jdk ECdsa sign:" + Hex.encodeHexString(result));//把内容转成16进制
            
            //3.验证签名
            X509EncodedKeySpec X509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(X509EncodedKeySpec);
            signature = Signature.getInstance("SHA1withECDSA");
            signature.initVerify(publicKey);
            signature.update(MYSECURITY.getBytes());
            boolean flag = signature.verify(result);
            System.out.println("jdk ECdsa verify:" + flag);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
