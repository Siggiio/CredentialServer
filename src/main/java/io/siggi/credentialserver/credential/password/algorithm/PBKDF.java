/*!
 * This file is part of CredentialServer.
 *
 * CredentialServer is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * CredentialServer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with CredentialServer. If not, see <https://www.gnu.org/licenses/>.
 */
package io.siggi.credentialserver.credential.password.algorithm;

import io.siggi.credentialserver.credential.password.HashingAlgorithm;
import io.siggi.credentialserver.util.Util;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class PBKDF implements HashingAlgorithm {

    public PBKDF() {
    }

    private static byte[] genSalt() {
        byte[] salt = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        return salt;
    }

    private static byte[] hashPassword(final char[] password, final byte[] salt, final int iterations, final int keyLength) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] res = key.getEncoded();
            return res;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getName() {
        return "PBKDF";
    }

    @Override
    public String hash(char[] password) {
        int iterations = 100;
        int keyLength = 32 * 8;
        byte[] saltBytes = genSalt();
        byte[] hashed = hashPassword(password, saltBytes, iterations, keyLength);
        return Util.hex(hashed) + ";" + Util.hex(saltBytes) + ";" + iterations + ";" + keyLength;
    }

    @Override
    public boolean verify(char[] password, String hash) {
        try {
            String[] parts = hash.split(";");
            byte[] hashData = Util.unhex(parts[0]);
            String salt = parts[1];
            int iterations = Integer.parseInt(parts[2]);
            int keyLength = Integer.parseInt(parts[3]);
            byte[] saltBytes = Util.unhex(salt);
            byte[] hashed = hashPassword(password, saltBytes, iterations, keyLength);
            return Arrays.equals(hashData, hashed);
        } catch (Exception e) {
            return false;
        }
    }
}
