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

import io.siggi.credentialserver.credential.CredentialSession;
import io.siggi.credentialserver.credential.CredentialType;
import io.siggi.credentialserver.credential.User;

import java.util.UUID;

public class CredentialTypeTOTP extends CredentialType<CredentialTOTP> {

    private static final long TEN_MINUTES = 60L * 10L * 1000L;

    private static boolean validate(long firstStep, long lastStep, byte[] key, String enteredCode) {
        for (long step = firstStep; step <= lastStep; step++) {
            if (TOTP.getOTP(step, key).equals(enteredCode)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String getType() {
        return "totp";
    }

    @Override
    public String startRegistration(User user) {
        CredentialSession session = user.getCredentialSession("totp", true, TEN_MINUTES, TEN_MINUTES);
        String randomKey = TOTP.randomKey();
        session.setData(randomKey);
        return randomKey;
    }

    @Override
    public CredentialTOTP finishRegistration(User user, String data) {
        CredentialSession session = user.getCredentialSession("totp", true, TEN_MINUTES, 0L);
        String secret = session.getData();
        byte[] key;
        try {
            key = Base32.decode(secret);
        } catch (Base32.DecodingException | NullPointerException e) {
            return null;
        }
        long now = System.currentTimeMillis();
        long lastStep = (now / 30000L);
        long firstStep = lastStep - 2L;
        if (!validate(firstStep, lastStep, key, data)) {
            return null;
        }
        session.delete();
        CredentialTOTP credential = new CredentialTOTP(secret);
        credential.recordUse();
        user.addCredential(credential);
        return credential;
    }

    @Override
    public String startLogin(User user) {
        return null;
    }

    @Override
    public CredentialTOTP finishLogin(User user, String data) {
        long now = System.currentTimeMillis();
        long lastStep = (now / 30000L);
        String enteredCode = data.replace(" ", "");
        for (CredentialTOTP credential : user.getCredentials(CredentialTOTP.class)) {
            long lastUse = credential.getLastUse();
            long minimumStep = (lastUse / 30000L) + 1L;
            long firstStep = Math.max(minimumStep, lastStep - 2L);
            byte[] key;
            try {
                key = Base32.decode(credential.secret);
            } catch (Base32.DecodingException e) {
                continue;
            }
            if (validate(firstStep, lastStep, key, enteredCode)) {
                credential.recordUse();
                return credential;
            }
        }
        return null;
    }

    @Override
    public CredentialTOTP deserialize(String secret, UUID uuid, String name, long useCount, long lastUse, long expires) {
        return new CredentialTOTP(uuid, name, useCount, lastUse, expires, secret);
    }

    @Override
    public Class<CredentialTOTP> getTypeClass() {
        return CredentialTOTP.class;
    }
}
