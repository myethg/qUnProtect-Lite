package qp.deob;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public final class Crypto {
    private Crypto() {}

    public static String aesDecrypt(byte[] iv, String pw, String b64) throws Exception {
        byte[] blob = Base64.getDecoder().decode(b64);
        byte[] salt = Arrays.copyOfRange(blob, 0, 16);
        byte[] ct = Arrays.copyOfRange(blob, 32, blob.length);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey derived = skf.generateSecret(new PBEKeySpec(pw.toCharArray(), salt, 1, 256));
        SecretKeySpec key = new SecretKeySpec(derived.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
    }
}
