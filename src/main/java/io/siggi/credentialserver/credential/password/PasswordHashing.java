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
package io.siggi.credentialserver.credential.password;

import io.siggi.credentialserver.credential.password.algorithm.PBKDF;
import io.siggi.credentialserver.credential.password.algorithm.Plain;

import java.util.HashMap;
import java.util.Map;

public class PasswordHashing {

    private static final HashingAlgorithm defaultAlgorithm;
    private static final Map<String, HashingAlgorithm> algorithms = new HashMap<>();

    static {
        addAlgorithm(defaultAlgorithm = new PBKDF());
        addAlgorithm(new Plain());
    }

    private static void addAlgorithm(HashingAlgorithm algorithm) {
        algorithms.put(algorithm.getName(), algorithm);
    }

    public static String hash(char[] password) {
        return defaultAlgorithm.getName() + ";" + defaultAlgorithm.hash(password);
    }

    public static boolean verify(char[] password, String hash) {
        if (password == null || hash == null) {
            return false;
        }
        int i = hash.indexOf(";");
        if (i == -1) return false;
        String algorithm = hash.substring(0, i);
        hash = hash.substring(i + 1);
        HashingAlgorithm hashingAlgorithm = algorithms.get(algorithm);
        if (hashingAlgorithm == null)
            return false;
        return hashingAlgorithm.verify(password, hash);
    }
}
