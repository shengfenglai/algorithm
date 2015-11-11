package com.lsf.main;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Hex;

public class DSAImpl {
    
    private static final String MYSECURITY = "HELLOWORLD";

    public static void main(String[] args) {
        dsaWithJDKImpl();
    }
    
    
    public static void dsaWithJDKImpl(){
        try {
            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            DSAPublicKey dsaPublicKey = (DSAPublicKey) keyPair.getPublic();  
            DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) keyPair.getPrivate();
            //2.执行签名
            PKCS8EncodedKeySpec  pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(dsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("DSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA1withDSA");
            signature.initSign(privateKey);
            signature.update(MYSECURITY.getBytes());
            byte[] result = signature.sign();
            System.out.println("jdk dsa sign:" + Hex.encodeHexString(result));//把内容转成16进制
            
            //3.验证签名
            X509EncodedKeySpec X509EncodedKeySpec = new X509EncodedKeySpec(dsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("DSA");
            PublicKey publicKey = keyFactory.generatePublic(X509EncodedKeySpec);
            signature = Signature.getInstance("SHA1withDSA");
            signature.initVerify(publicKey);
            signature.update(MYSECURITY.getBytes());
            boolean flag = signature.verify(result);
            System.out.println("jdk dsa verify:" + flag);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
