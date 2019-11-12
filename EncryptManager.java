package com.example.paymun;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.KeyFactory;
import javax.crypto.Cipher;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import static java.nio.charset.StandardCharsets.UTF_8;
import android.util.Base64;
import java.security.interfaces.RSAPrivateKey;



public class EncryptManager {
    KeyPairGenerator keyPairGenerator;
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048 /*, new SecureRandom()*/);
        KeyPair pair = generator.generateKeyPair();
        return  pair;
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes());
        return Base64.encodeToString(cipherText, Base64.DEFAULT);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.decode(cipherText, Base64.DEFAULT);
        Cipher decriptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "BC");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decriptCipher.doFinal(bytes));
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();
        return Base64.encodeToString(signature, Base64.DEFAULT);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.decode(signature, Base64.DEFAULT);
        return publicSignature.verify(signatureBytes);
    }

    public static String publicKeyString(PublicKey pubKey) {
        String result = "";
        try {
            byte[] publicKey = pubKey.getEncoded();
            byte[] publicKey64  = Base64.encode(publicKey, Base64.DEFAULT);
            String publicKeyString = new String(publicKey64);
            result = "-----BEGIN PUBLIC KEY-----\n" + publicKeyString + "-----END PUBLIC KEY-----\n";
        }
        catch ( Exception exc){
            result = exc.getMessage();
        }
        return result;
    }

    public static PublicKey publicKeyFromString(String publickey)
    {
        String pubKeyPEM = publickey.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("-----END PUBLIC KEY-----", "");
        try {
            // Base64 decode the data
            byte[] encodedPublicKey = Base64.decode(pubKeyPEM, Base64.DEFAULT);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedPublicKey);
            KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            return  null;
        }
    }

    public static PrivateKey privateKeyFromString(String privatekey)
    {
        String priPEM = privatekey.replace("-----BEGIN PRIVATE KEY-----\n", "").replace("-----END PRIVATE KEY-----", "");
        try {
            // Base64 decode the data
            byte[] encodedPrivateKey = Base64.decode(priPEM , Base64.DEFAULT);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            return  null;
        }
    }

    public static String privateKeyString(PrivateKey priKey) {
        String result = "";
        try {
            byte[] key = priKey.getEncoded();
            byte[] key64 = Base64.encode(key, Base64.DEFAULT);
            String privateKeyString = new String(key64);
            result = "-----BEGIN PRIVATE KEY-----\n" + privateKeyString + "-----END PRIVATE KEY-----\n";
        }
        catch ( Exception exc){
            result = exc.getMessage();
        }
        return result;
    }
}


class test{
    public void test(){
        try {
            String publicK = "-----BEGIN PUBLIC KEY-----\n"
                    + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0R8eP6EXsIZoqfuzDyEJ\n"
                    + "ZNC9vX7mHo33cGjcEEzuaHcKBmGr1IdIQkRRpGyAJDihvnyO6j8LWh7fbZvEeV+M\n"
                    + "NY63Ueq99n0oMII4+YYQhN0iDjCtMpGjmW44rLU3QbLymMTDM6Y8GLlCQS0Td6p8\n"
                    + "xFq/x1qIwIq2SoxGyLcWqe5NMqHQBtY2eFN0/mwANTmXy4T6nxUVTo1gdSmkiknU\n"
                    + "ZNlNXMg5Se/pHJ4FtALzb9Xt8z7H366uF2R2N5K9Tpf6n3FO2OF32hh+7KqqjxkQ\n"
                    + "WhnM+KlxwVxHdjrhf/JfibQhQaqxc3jHQaAWCImlaOqlQDMrlHwFaMa+/7pV7M0g\n"
                    + "/QIDAQAB\n"
                    + "-----END PUBLIC KEY-----";

            String privateK = "-----BEGIN PRIVATE KEY-----\n"
                    + "MIIEpAIBAAKCAQEA0R8eP6EXsIZoqfuzDyEJZNC9vX7mHo33cGjcEEzuaHcKBmGr\n"
                    + "1IdIQkRRpGyAJDihvnyO6j8LWh7fbZvEeV+MNY63Ueq99n0oMII4+YYQhN0iDjCt\n"
                    + "MpGjmW44rLU3QbLymMTDM6Y8GLlCQS0Td6p8xFq/x1qIwIq2SoxGyLcWqe5NMqHQ\n"
                    + "BtY2eFN0/mwANTmXy4T6nxUVTo1gdSmkiknUZNlNXMg5Se/pHJ4FtALzb9Xt8z7H\n"
                    + "366uF2R2N5K9Tpf6n3FO2OF32hh+7KqqjxkQWhnM+KlxwVxHdjrhf/JfibQhQaqx\n"
                    + "c3jHQaAWCImlaOqlQDMrlHwFaMa+/7pV7M0g/QIDAQABAoIBAB83oT0X5/Co2+J2\n"
                    + "KbB6OswDMjPhx+nrQPMVoDZJubQ8AvHZbjxzdni3+KUOMmHV12VXdEEpKKFrJujW\n"
                    + "njGNLyHGnHycyX9Mhy2Ynvc2yWwAE8ehAhXgslai4tB7W9SRqU/fXZFuAR4it66B\n"
                    + "k1yjhW0NbAAPNodhnZ1Ky/1GAZrbrBagXoBcRRfGAPivHRGXDx3+YlmLp+a7LljR\n"
                    + "17nki0kysCc/kl8iz5vYJh9v9JP2gC+dA9cW/58/yGCP2Up/2gvVYdvOCwmx1ojd\n"
                    + "BqY7T1ypCbrFJU9idK7jsoNW9t0oGrfu1IVuYQC/WTTjVsODswYPh4jVxVPT8apm\n"
                    + "J0lgVGECgYEA2oY7IIaeILA2Erg5UlksUEB/67HfR6V45dqujSBbRs0WPOiRcrVW\n"
                    + "1FyWhL9JGJRZ7d+gMpSWzLEP4k6tz6bz/cZzi+s8RYAD/fmBFEfju2yOWBxCKzaC\n"
                    + "p5sV2W1H5256Kvb8fXDTIDuYm3f4wS9OmibyQsGowsWF/yyQl58ZCyECgYEA9PwU\n"
                    + "zhxF47Wtby7LthPI3CbOVXFDPdlAaVv4Ejuq8g4rSsGO6P95F4G2RMM96Dsd5jUY\n"
                    + "WMdsnghLanwQy39g7uBEgYMTVPb+qvFhqbawJsa9z8H1TWW7RnkXxG+0MQUitz9a\n"
                    + "+R7uC69z1Ons+fKXwepT7+K7wgeulhDvdtcXVl0CgYEAi+dAV5SYDEmEdPupB0W8\n"
                    + "Dy0cOOPKFW6lNlOJSSUcCvomcJxc8lmS26bjXt2wiKIB6T8wqvFikm4Rw0uoD7fN\n"
                    + "of254Cyci8pnw+RHdZqI/GeFwndlDZF6mJ+7n1ZNoKekY3l5MT5YjNxa2b43bkdB\n"
                    + "RYQFuiOOThRzs2jusYPUXsECgYEA7HFvUw4Olht+bFRp4C1wKqp5chWCpGrNs+JD\n"
                    + "prVX446xUdFGMLKBGKLkW7FkSoLj9I9CFE1FE7FFuFxNiVpDH8nr1GPBgLtyR2H4\n"
                    + "tGfR01r1T1MPgcex2+57deeprbYbL2lCUDX94eFQlim/wezVcx7KLDhUpovrgIKP\n"
                    + "2870gzECgYAEaLazG4JsG9ZrKngbPj+sw/lK6p5q9DmIrJGjKJuvJb346I12LQlb\n"
                    + "tCHspN14wH5Rn/TrofH3GrFOrkcfEU8bgHRu1AGZRaHlqTRlkaeA84Fs6qoq1/zf\n"
                    + "fI98Jadd+NvH/5630COV2RpWcVPT0Q4nnCyuw8RnZ5vKKEIXe2k//w==\n"
                    + "-----END PRIVATE KEY-----";

            EncryptManager pkManager = new EncryptManager();
            PublicKey publicKey = pkManager.publicKeyFromString(publicK);
            PrivateKey privateKey = pkManager.privateKeyFromString(privateK);

            String sPubkey = pkManager.publicKeyString(publicKey);
            String sPriKey = pkManager.privateKeyString(privateKey);

            //Our secret message
            String message = "the answer to life the universe and everything";

            //Encrypt the message
            String cipherText = pkManager.encrypt(message, publicKey);
            //System.out.println(cipherText);

            String decipheredMessage = pkManager.decrypt(cipherText, privateKey);
            //System.out.println(decipheredMessage);
        } catch (Exception e){ }
    }
}

