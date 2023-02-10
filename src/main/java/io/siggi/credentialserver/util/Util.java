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
package io.siggi.credentialserver.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.UUID;

public final class Util {

    private static final char[] hexSet = "0123456789abcdef".toCharArray();

    private Util() {
    }

    public static String hex(byte[] data) {
        char[] chars = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            chars[i * 2] = hexSet[(data[i] >> 4) & 0xf];
            chars[i * 2 + 1] = hexSet[data[i] & 0xf];
        }
        return new String(chars);
    }

    public static byte[] unhex(String hex) {
        int length = hex.length();
        if (length % 2 != 0)
            throw new IllegalArgumentException("Invalid hex string");
        length /= 2;
        try {
            byte[] data = new byte[length];
            for (int i = 0; i < length; i++) {
                data[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return data;
        } catch (NumberFormatException nfe) {
            throw new IllegalArgumentException("Invalid hex string");
        }
    }

    public static UUID uuidFromString(String uuid) {
        return UUID.fromString(
                uuid.replace("-", "")
                        .replaceAll("([0-9A-Fa-f]{8})([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})([0-9A-Fa-f]{12})", "$1-$2-$3-$4-$5")
        );
    }

    public static String uuidToString(UUID uuid) {
        return uuid.toString().replace("-", "");
    }

    public static byte[] readFully(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copy(in, out);
        return out.toByteArray();
    }

    public static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] b = new byte[4096];
        int c;
        while ((c = in.read(b, 0, b.length)) != -1) {
            out.write(b, 0, c);
        }
    }

    public static boolean isJson(String data) {
        data = data.trim();
        return data.equals("null") || data.equals("true") || data.equals("false")
                || data.matches("-?[0-9]{1,}(\\.[0-9]*)?(e[+-][0-9]{1,})?")
                || data.startsWith("{") || data.startsWith("[");
    }
}
