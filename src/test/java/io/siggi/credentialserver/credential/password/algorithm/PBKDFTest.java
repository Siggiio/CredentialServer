package io.siggi.credentialserver.credential.password.algorithm;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PBKDFTest {
    @Test
    public void verifyAgainstPresetHash() {
        String hashOfCookies = "d7865b915bf763e5bc0dead87d375b6ac01a15a98b66124dbbd0d02fef09cb00;bab3e5187e1d28b611bec7d36e61308788a419d7262c83ec77233d30836ab36c;100;256";
        assertTrue(new PBKDF().verify("cookies".toCharArray(), hashOfCookies));
        assertFalse(new PBKDF().verify("biscuits".toCharArray(), hashOfCookies));
    }

    @Test
    public void generateHashAndVerify() {
        char[] cookies = "cookies".toCharArray();
        char[] biscuits = "biscuits".toCharArray();
        String hashOfCookies = new PBKDF().hash(cookies);
        assertTrue(new PBKDF().verify(cookies, hashOfCookies));
        assertFalse(new PBKDF().verify(biscuits, hashOfCookies));
    }
}
