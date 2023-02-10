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
package io.siggi.credentialserver.credential.webauthn;

import io.siggi.credentialserver.credential.CredentialType;
import io.siggi.credentialserver.credential.User;

import java.util.UUID;

public class CredentialTypeWebAuthn extends CredentialType<CredentialWebAuthn> {

    @Override
    public String getType() {
        return "webauthn";
    }

    @Override
    public String startRegistration(User user) {
        return user.getNamespace().getWebAuthn().startRegistration(user);
    }

    @Override
    public CredentialWebAuthn finishRegistration(User user, String data) {
        try {
            return user.getNamespace().getWebAuthn().finishRegistration(user, data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String startLogin(User user) {
        return user.getNamespace().getWebAuthn().startLogin(user);
    }

    @Override
    public CredentialWebAuthn finishLogin(User user, String data) {
        try {
            return user.getNamespace().getWebAuthn().finishLogin(user, data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public CredentialWebAuthn deserialize(String key, UUID uuid, String name, long useCount, long lastUse, long expires) {
        return new CredentialWebAuthn(uuid, name, useCount, lastUse, expires, key);
    }

    @Override
    public Class<CredentialWebAuthn> getTypeClass() {
        return CredentialWebAuthn.class;
    }
}
