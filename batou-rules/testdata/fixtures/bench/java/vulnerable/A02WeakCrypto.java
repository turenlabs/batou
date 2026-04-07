// Source: CWE-327 - Use of broken cryptographic algorithm
// Expected: BATOU-CRY-001 (Weak Hashing - MD5), BATOU-CRY-003 (Weak Cipher - DES)
// OWASP: A02:2021 - Cryptographic Failures

package com.example.vulnerable;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;

public class A02WeakCrypto {

    public static String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] encryptData(byte[] data, String key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    public static String generateToken(int userId) {
        Random random = new Random(userId);
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            token.append(Integer.toHexString(random.nextInt(16)));
        }
        return token.toString();
    }
}
