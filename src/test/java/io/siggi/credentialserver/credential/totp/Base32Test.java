package io.siggi.credentialserver.credential.totp;

// While Base32 is technically not my own code, I believe I can still write test
// cases to make sure it is doing what I want it to do.

import io.siggi.credentialserver.util.Util;
import java.nio.charset.StandardCharsets;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class Base32Test {
    @Test
    public void encodesAndDecodesCorrectly() {
        BiConsumer<String, String> encodeTest = (raw, encoded) -> {
            assertEquals(encoded, Base32.encode(raw.getBytes(StandardCharsets.UTF_8)));
            try {
                assertEquals(raw, new String(Base32.decode(encoded), StandardCharsets.UTF_8));
            } catch (Base32.DecodingException e) {
                throw new RuntimeException(e);
            }
        };
        // RFC 4648 examples with padding removed
        encodeTest.accept("", "");
        encodeTest.accept("f", "MY");
        encodeTest.accept("fo", "MZXQ");
        encodeTest.accept("foo", "MZXW6");
        encodeTest.accept("foob", "MZXW6YQ");
        encodeTest.accept("fooba", "MZXW6YTB");
        encodeTest.accept("foobar", "MZXW6YTBOI");
    }
}
