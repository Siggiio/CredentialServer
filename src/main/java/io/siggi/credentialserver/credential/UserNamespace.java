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

import io.siggi.credentialserver.CredentialServer;
import io.siggi.credentialserver.credential.webauthn.WebAuthn;
import io.siggi.credentialserver.storage.Storage;
import io.siggi.credentialserver.storage.StorageException;
import io.siggi.credentialserver.storage.StorageFile;
import io.siggi.credentialserver.storage.StorageMySQL;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

public final class UserNamespace {
    private final CredentialServer server;
    private final String name;
    private final File directory;
    private final Storage storage;
    private final WebAuthn webAuthn;

    public UserNamespace(CredentialServer server, String name, File directory) {
        this.server = server;
        this.name = name;
        this.directory = directory;

        Properties configuration = new Properties();
        try (FileInputStream in = new FileInputStream(new File(directory, "config.txt"))) {
            configuration.load(in);
        } catch (Exception e) {
            throw new RuntimeException("Unable to read config", e);
        }
        String webAuthnName = configuration.getProperty("webauthn-name");
        String webAuthnId = configuration.getProperty("webauthn-id");
        Set<String> webAuthnOrigins = new HashSet<>();
        String webAuthnOrigin = configuration.getProperty("webauthn-origin");
        if (webAuthnOrigin != null) webAuthnOrigins.add(webAuthnOrigin);
        if (webAuthnId != null && webAuthnName != null && !webAuthnOrigins.isEmpty()) {
            this.webAuthn = new WebAuthn(webAuthnId, webAuthnName, webAuthnOrigins);
        } else {
            this.webAuthn = null;
        }
        String storageBackend = configuration.getProperty("storage");
        if (storageBackend == null) storageBackend = "file";
        switch (storageBackend) {
            case "file":
                this.storage = new StorageFile(new File(directory, "users"), server.tmpDirectory);
                break;
            case "mysql":
                this.storage = new StorageMySQL(configuration);
                break;
            default:
                throw new RuntimeException("Unknown storage backend " + storageBackend);
        }
    }

    public String getName() {
        return name;
    }

    public WebAuthn getWebAuthn() {
        return webAuthn;
    }

    public User readUser(UUID uuid) throws StorageException {
        User user = storage.readUser(uuid);
        user.namespace = this;
        user.uuid = uuid;
        for (Credential credential : user.getCredentials()) {
            credential.user = user;
        }
        for (CredentialSession session : user.getCredentialSessions()) {
            session.user = user;
        }
        return user;
    }

    public void saveUser(User user) throws StorageException {
        if (!user.hasChanged()) return;
        storage.saveUser(user.uuid, user);
    }
}
