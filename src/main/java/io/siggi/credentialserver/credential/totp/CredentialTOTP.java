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
package io.siggi.credentialserver.credential.totp;

import io.siggi.credentialserver.credential.Credential;

import java.util.UUID;

public final class CredentialTOTP extends Credential {
    public final String secret;

    public CredentialTOTP(String secret) {
        this(UUID.randomUUID(), null, 0L, 0L, 0L, secret);
    }

    public CredentialTOTP(UUID uuid, String name, long useCount, long lastUse, long expires, String secret) {
        super("totp", uuid, name, useCount, lastUse, expires);
        this.secret = secret;
    }

    @Override
    public String getData() {
        return secret;
    }
}
