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

import java.util.UUID;

public final class CredentialPassword extends Credential {
    public final String hash;

    public CredentialPassword(String password) {
        this(UUID.randomUUID(), null, 0L, 0L, 0L, PasswordHashing.hash(password.toCharArray()));
    }

    public CredentialPassword(UUID uuid, String name, long useCount, long lastUse, long expires, String hash) {
        super("password", uuid, name, useCount, lastUse, expires);
        this.hash = hash;
    }

    @Override
    public String getData() {
        return hash;
    }
}
