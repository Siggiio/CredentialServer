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

import io.siggi.credentialserver.credential.Credential;
import io.siggi.credentialserver.credential.CredentialType;
import io.siggi.credentialserver.credential.User;

import java.util.List;
import java.util.UUID;

public class CredentialTypePassword extends CredentialType<CredentialPassword> {

    @Override
    public String getType() {
        return "password";
    }

    @Override
    public String startRegistration(User user) {
        return null;
    }

    @Override
    public CredentialPassword finishRegistration(User user, String data) {
        CredentialPassword password = new CredentialPassword(data);
        List<Credential> passwordCredentials = user.getCredentials("password");
        passwordCredentials.forEach(Credential::delete);
        user.addCredential(password);
        return password;
    }

    @Override
    public String startLogin(User user) {
        return null;
    }

    @Override
    public CredentialPassword finishLogin(User user, String data) {
        char[] chars = data.toCharArray();
        for (CredentialPassword password : user.getCredentials(CredentialPassword.class)) {
            if (PasswordHashing.verify(chars, password.hash)) {
                password.recordUse();
                return password;
            }
        }
        return null;
    }

    @Override
    public CredentialPassword deserialize(String hash, UUID uuid, String name, long useCount, long lastUse, long expires) {
        return new CredentialPassword(uuid, name, useCount, lastUse, expires, hash);
    }

    @Override
    public Class<CredentialPassword> getTypeClass() {
        return CredentialPassword.class;
    }
}
