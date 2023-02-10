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

import io.siggi.credentialserver.credential.Credential;

import java.util.UUID;

public class CredentialWebAuthn extends Credential {

    public final String key;

    public CredentialWebAuthn(String key) {
        this(UUID.randomUUID(), null, 0L, 0L, 0L, key);
    }

    public CredentialWebAuthn(UUID uuid, String name, long useCount, long lastUse, long expires, String key) {
        super("webauthn", uuid, name, useCount, lastUse, expires);
        this.key = key;
    }

    @Override
    public String getData() {
        return key;
    }
}
