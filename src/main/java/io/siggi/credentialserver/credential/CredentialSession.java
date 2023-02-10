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

public final class CredentialSession {
    transient User user;
    private String type;
    private boolean registration;
    private String data;
    private long time;
    private long expiry;
    private transient boolean changed;
    private transient boolean deleted;

    public CredentialSession() {
    }

    public CredentialSession(String type, boolean registration, String data, long time, long expiry) {
        this.type = type;
        this.registration = registration;
        this.data = data;
        this.time = time;
        this.expiry = expiry;
    }

    public String getType() {
        return type;
    }

    public boolean isRegistration() {
        return registration;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
        markAsChanged();
    }

    public long getTime() {
        return time;
    }

    public long getExpiry() {
        return expiry;
    }

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
