package io.siggi.credentialserver.credential.password.algorithm;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PlainTest {
    @Test
    public void verifyAgainstPresetHash() {
        assertTrue(new Plain().verify("correct".toCharArray(), "correct"));
        assertFalse(new Plain().verify("wrong".toCharArray(), "totally-incorrect"));
    }

    @Test
    public void generateHashAndVerify() {
        char[] cookies = "cookies".toCharArray();
        char[] biscuits = "biscuits".toCharArray();
        String hashOfCookies = new Plain().hash(cookies);
        assertTrue(new Plain().verify(cookies, hashOfCookies));
        assertFalse(new Plain().verify(biscuits, hashOfCookies));
    }
}
