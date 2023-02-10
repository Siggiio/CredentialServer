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
package io.siggi.credentialserver.apiresponses;

import io.siggi.credentialserver.credential.Credential;

import java.util.UUID;

/**
 * A ClientsideCredential does not include any secret data.
 */
public class ClientsideCredential {
    public UUID credential;
    public String name;
    public String type;
    public long useCount;
    public long lastUse;

    public ClientsideCredential() {
    }

    public ClientsideCredential(Credential credential) {
        this.credential = credential.getUUID();
        this.name = credential.getName();
        this.type = credential.getType();
        this.useCount = credential.getUseCount();
        this.lastUse = credential.getLastUse();
    }
}
