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
package io.siggi.credentialserver.credential;

import io.siggi.credentialserver.credential.password.CredentialTypePassword;
import io.siggi.credentialserver.credential.totp.CredentialTypeTOTP;
import io.siggi.credentialserver.credential.webauthn.CredentialTypeWebAuthn;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public abstract class CredentialType<T extends Credential> {
    private static final Map<String, CredentialType> types = new HashMap<>();

    static {
        addType(new CredentialTypePassword());
        addType(new CredentialTypeTOTP());
        addType(new CredentialTypeWebAuthn());
    }

    private static void addType(CredentialType type) {
        types.put(type.getType(), type);
    }

    public static <T extends CredentialType> T get(String type) {
        return (T) types.get(type);
    }

    public static Map<String, CredentialType> getTypes() {
        return Collections.unmodifiableMap(types);
    }

    public abstract String getType();

    public abstract String startRegistration(User user);

    public abstract T finishRegistration(User user, String data);

    public abstract String startLogin(User user);

    public abstract T finishLogin(User user, String data);

    public abstract T deserialize(String data, UUID uuid, String name, long useCount, long lastUse, long expires);

    public abstract Class<T> getTypeClass();
}
