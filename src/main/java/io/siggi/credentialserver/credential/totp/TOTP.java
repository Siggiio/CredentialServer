package io.siggi.credentialserver.credential.totp;

// https://github.com/taimos/totp/blob/master/src/main/java/de/taimos/totp/TOTP.java

import io.siggi.credentialserver.util.Util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class TOTP {

    private TOTP() {
    }

    public static String randomKey() {
        byte[] key = new byte[20];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return Base32.encode(key);
    }

    public static boolean validate(final byte[] key, final String otp) {
        return validate(getStep(), key, otp);
    }

    public static boolean validate(final String key, final String otp) {
        try {
            return validate(Base32.decode(key), otp);
        } catch (Base32.DecodingException e) {
            return false;
        }
    }

    public static boolean validate(final long step, final byte[] key, final String otp) {
        return getOTP(step, key).equals(otp) || getOTP(step - 1, key).equals(otp);
    }

    private static long getStep() {
        // 30 seconds StepSize (ID TOTP)
        return System.currentTimeMillis() / 30000;
    }

    public static String getOTP(final long step, final byte[] key) {
        String periodNumber = Long.toHexString(step).toUpperCase();
        while (periodNumber.length() < 16) {
            periodNumber = "0" + periodNumber;
        }

        final byte[] msg = Util.unhex(periodNumber);
        final byte[] hash = hmac_sha1(key, msg);

        // put selected bytes into result int
        final int offset = hash[hash.length - 1] & 0xf;
        final int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
        final int otp = binary % 1000000;

        String result = Integer.toString(otp);
        while (result.length() < 6) {
            result = "0" + result;
        }
        return result;
    }

    /**
     * This method uses the JCE to provide the crypto algorithm. HMAC computes a
     * Hashed Message Authentication Code with the crypto hash algorithm as a
     * parameter.
     *
     * @param keyBytes the bytes to use for the HMAC key
     * @param text     the message or text to be authenticated.
     */
    private static byte[] hmac_sha1(final byte[] keyBytes, final byte[] text) {
        try {
            final Mac hmac = Mac.getInstance("HmacSHA1");
            final SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (final GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }
}
