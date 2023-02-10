package io.siggi.credentialserver.credential.totp;

// While TOTP is technically not my own code, I believe I can still write test
// cases to make sure it is doing what I want it to do.

import io.siggi.credentialserver.util.Util;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TOTPTest {
    @Test
    public void generatesCorrectCodes() {
        byte[] key = Util.unhex("000102030405060708090a0b0c0d0e0f");
        // When encoded as Base32, this key is AAAQEAYEAUDAOCAJBIFQYDIOB4
        assertEquals("783978", TOTP.getOTP(1L, key));
        assertEquals("131230", TOTP.getOTP(10L, key));
        assertEquals("108465", TOTP.getOTP(100L, key));
        assertEquals("037150", TOTP.getOTP(200L, key));
        assertEquals("824742", TOTP.getOTP(1000L, key));
    }
}
