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
package io.siggi.credentialserver.storage;

import io.siggi.credentialserver.credential.User;
import io.siggi.credentialserver.serialization.Serialization;
import io.siggi.credentialserver.util.Util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class StorageFile extends Storage {

    private final File userDirectory;
    private final File tmpDirectory;

    public StorageFile(File userDirectory, File tmpDirectory) {
        this.userDirectory = userDirectory;
        this.tmpDirectory = tmpDirectory;
    }

    private final File getUserFile(UUID uuid) {
        String uuidString = uuid.toString().toLowerCase().replace("-", "");
        return new File(userDirectory, uuidString.substring(0, 2) + "/" + uuidString.substring(2, 4) + "/" + uuidString + ".json");
    }

    @Override
    public User readUser(UUID uuid) throws StorageException {
        if (uuid == null)
            throw new NullPointerException("uuid cannot be null");
        File userFile = getUserFile(uuid);
        if (!userFile.exists()) {
            return new User();
        }
        try (FileInputStream in = new FileInputStream(userFile)) {
            String data = new String(Util.readFully(in), StandardCharsets.UTF_8);
            return Serialization.deserialize(data, User.class);
        } catch (Exception e) {
            throw new StorageException("Unable to read user", e);
        }
    }

    @Override
    public void saveUser(UUID uuid, User user) throws StorageException {
        if (uuid == null || user == null)
            throw new NullPointerException("uuid, user cannot be null");
        File temporaryFile = new File(tmpDirectory, UUID.randomUUID().toString());
        try {
            File userFile = getUserFile(uuid);
            File parentFile = userFile.getParentFile();
            if (!parentFile.exists())
                parentFile.mkdirs();
            try (FileOutputStream out = new FileOutputStream(temporaryFile)) {
                out.write(Serialization.serialize(user, true).getBytes(StandardCharsets.UTF_8));
            }
            temporaryFile.renameTo(userFile);
        } catch (Exception e) {
            throw new StorageException("Unable to write user", e);
        } finally {
            if (temporaryFile.exists())
                temporaryFile.delete();
        }
    }
}
