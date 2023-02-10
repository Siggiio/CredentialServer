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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class User {
    private final Map<String, String> variables = new HashMap<>();
    private transient final Set<String> changedVariables = new HashSet<>();
    private final List<Credential> credentials = new ArrayList<>();
    private final Map<String, CredentialSession> credentialSessions = new HashMap<>();
    transient UserNamespace namespace;
    transient UUID uuid;
    transient boolean changed = false;

    public String getDisplayName() {
        String name = getVariable("name");
        if (name == null) {
            return uuid.toString();
        }
        return name;
    }

    public Map<String, String> getVariables() {
        return variables;
    }

    public UserNamespace getNamespace() {
        return namespace;
    }

    public UUID getUUID() {
        return uuid;
    }

    public String getVariable(String key) {
        return variables.get(key);
    }

    public void setVariable(String key, String value) {
        if (key == null) throw new NullPointerException();
        changedVariables.add(key);
        if (value == null)
            variables.remove(key);
        else
            variables.put(key, value);
        markAsChanged();
    }

    public Set<String> getChangedVariables() {
        return changedVariables;
    }

    public List<Credential> getCredentials() {
        return Collections.unmodifiableList(credentials);
    }

    public <T extends Credential> List<T> getCredentials(Class<T> type) {
        List<T> list = new ArrayList<>();
        for (Iterator<Credential> it = credentials.iterator(); it.hasNext(); ) {
            Credential credential = it.next();
            if (credential == null) {
                it.remove();
                continue;
            }
            if (type.isAssignableFrom(credential.getClass())) {
                list.add((T) credential);
            }
        }
        return list;
    }

    public <T extends Credential> List<T> getCredentials(String type) {
        List<T> list = new ArrayList<>();
        for (Iterator<Credential> it = credentials.iterator(); it.hasNext(); ) {
            Credential credential = it.next();
            if (credential == null) {
                it.remove();
                continue;
            }
            if (type.equals(credential.getType())) {
                list.add((T) credential);
            }
        }
        return list;
    }

    public Credential getCredential(UUID uuid) {
        if (uuid == null)
            return null;
        for (Credential credential : credentials) {
            if (credential.getUUID().equals(uuid)) {
                return credential;
            }
        }
        return null;
    }

    public void addCredential(Credential credential) {
        credentials.add(credential);
        credential.user = this;
        credential.markAsChanged();
    }

    public CredentialSession getCredentialSession(String type, boolean registration, long validityPeriod, long expireEarlyPeriod) {
        long now = System.currentTimeMillis();
        String key = type + "-" + registration;
        CredentialSession credentialSession = validityPeriod <= expireEarlyPeriod ? null : credentialSessions.get(key);
        if (credentialSession == null || credentialSession.getExpiry() - expireEarlyPeriod < now) {
            credentialSessions.put(key, credentialSession = new CredentialSession(type, registration, null, now, now + validityPeriod));
            credentialSession.user = this;
        }
        return credentialSession;
    }

    public Collection<CredentialSession> getCredentialSessions() {
        return credentialSessions.values();
    }

    public Map<String, CredentialSession> getCredentialSessionsMap() {
        return credentialSessions;
    }

    public void markAsChanged() {
        changed = true;
    }

    public void markAsNotChanged() {
        changed = false;
        for (Credential credential : credentials) {
            credential.markAsNotChanged();
        }
        for (CredentialSession session : credentialSessions.values()) {
            session.markAsNotChanged();
        }
    }

    public boolean hasChanged() {
        boolean value = changed;
        changed = false;
        return value;
    }
}
