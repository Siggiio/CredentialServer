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

import java.util.UUID;

public abstract class Credential {
    private final UUID uuid;
    private final String type;
    private final long expires;
    transient User user;
    private String name;
    private long useCount;
    private long lastUse;
    private transient boolean changed = false;
    private transient boolean deleted = false;

    public Credential(String type, UUID uuid, String name, long useCount, long lastUse, long expires) {
        this.uuid = uuid;
        this.type = type;
        this.name = name;
        this.useCount = useCount;
        this.lastUse = lastUse;
        this.expires = expires;
    }

    public final String getType() {
        return type;
    }

    public final String getName() {
        return name;
    }

    public final void setName(String name) {
        this.name = name;
        markAsChanged();
    }

    public final void recordUse() {
        useCount += 1;
        lastUse = System.currentTimeMillis();
        markAsChanged();
    }

    public final long getUseCount() {
        return useCount;
    }

    public final long getLastUse() {
        return lastUse;
    }

    public final long getExpires() {
        return expires;
    }

    public final UUID getUUID() {
        return uuid;
    }

    public abstract String getData();

    public void markAsChanged() {
        if (user != null) user.markAsChanged();
        changed = true;
    }

    public void markAsNotChanged() {
        changed = false;
    }

    public boolean hasChanged() {
        boolean value = changed;
        changed = false;
        return value;
    }

    public void delete() {
        deleted = true;
        markAsChanged();
    }

    public boolean isDeleted() {
        return deleted;
    }
}
