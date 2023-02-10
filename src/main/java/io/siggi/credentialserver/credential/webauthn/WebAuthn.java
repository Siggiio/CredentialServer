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

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import io.siggi.credentialserver.credential.CredentialSession;
import io.siggi.credentialserver.credential.User;
import io.siggi.credentialserver.util.Util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class WebAuthn {

    private static final long TEN_MINUTES = 60L * 10L * 1000L;

    private final RelyingParty rp;
    private final ObjectMapper jsonMapper;
    private final ThreadLocal<User> userThreadLocal = new ThreadLocal<>();

    public WebAuthn(String id, String name, Set<String> origins) {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity
                .builder()
                .id(id)
                .name(name)
                .build();
        rp = RelyingParty
                .builder()
                .identity(rpIdentity)
                .credentialRepository(new CR())
                .origins(origins)
                .build();

        this.jsonMapper = new ObjectMapper()
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
                .setSerializationInclusion(Include.NON_ABSENT)
                .registerModule(new Jdk8Module());
    }

    private User getUser() {
        return userThreadLocal.get();
    }

    private CredentialSession getSession(boolean registration, boolean start) {
        long expireEarly = start ? TEN_MINUTES / 2L : 0L;
        return getUser().getCredentialSession("webauthn", registration, TEN_MINUTES, expireEarly);
    }

    private byte[] getHandleBytes(String name) {
        return name.getBytes(StandardCharsets.UTF_8);
    }

    private ByteArray getHandle(String name) {
        return new ByteArray(getHandleBytes(name));
    }

    private String getName(ByteArray handle) {
        return new String(handle.getBytes(), StandardCharsets.UTF_8);
    }

    private PublicKeyCredentialCreationOptions getCredentialCreationOptions(byte[] challenge) {
        User user = getUser();
        String name = user.getUUID().toString();
        String displayName = user.getDisplayName();
        ByteArray userHandle = getHandle(name);
        PublicKeyCredentialCreationOptions credentialCreationOptions = rp.startRegistration(
                StartRegistrationOptions
                        .builder()
                        .user(
                                UserIdentity.builder()
                                        .name(name)
                                        .displayName(displayName)
                                        .id(userHandle)
                                        .build()
                        )
                        .build()
        );
        if (challenge != null) {
            credentialCreationOptions = credentialCreationOptions.toBuilder().challenge(new ByteArray(challenge)).build();
        }
        return credentialCreationOptions;
    }

    private AssertionRequest getAssertionRequest(byte[] challenge) {
        User user = getUser();
        String name = user.getUUID().toString();
        ByteArray userHandle = getHandle(name);
        AssertionRequest assertionRequest = rp.startAssertion(StartAssertionOptions.builder()
                .username(Optional.of(name))
                .userHandle(userHandle)
                .build()
        );
        if (challenge != null) {
            assertionRequest = assertionRequest.toBuilder()
                    .publicKeyCredentialRequestOptions(
                            assertionRequest.getPublicKeyCredentialRequestOptions()
                                    .toBuilder()
                                    .challenge(new ByteArray(challenge))
                                    .build()
                    ).build();
        }
        return assertionRequest;
    }

    public String startRegistration(User user) {
        try {
            userThreadLocal.set(user);

            CredentialSession session = getSession(true, true);

            PublicKeyCredentialCreationOptions credentialCreationOptions;
            try {
                byte[] challenge = Util.unhex(session.getData());
                credentialCreationOptions = getCredentialCreationOptions(challenge);
            } catch (NullPointerException e) {
                credentialCreationOptions = getCredentialCreationOptions(null);
                session.setData(Util.hex(credentialCreationOptions.getChallenge().getBytes()));
            }
            try {
                return credentialCreationOptions.toCredentialsCreateJson();
            } catch (JsonProcessingException jpe) {
                throw new RuntimeException(jpe);
            }
        } finally {
            userThreadLocal.remove();
        }
    }

    public CredentialWebAuthn finishRegistration(User user, String json)
            throws IOException, RegistrationFailedException {
        try {
            userThreadLocal.set(user);
            String name = user.getDisplayName();
            CredentialSession session = getSession(true, false);

            json = fixResultJson(json, false);

            PublicKeyCredentialCreationOptions credentialCreationOptions;
            try {
                credentialCreationOptions = getCredentialCreationOptions(Util.unhex(session.getData()));
            } catch (Exception e) {
                return null;
            }

            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential
                    = PublicKeyCredential.parseRegistrationResponseJson(json);
            FinishRegistrationOptions registration = FinishRegistrationOptions.builder()
                    .request(credentialCreationOptions)
                    .response(credential)
                    .build();

            RegistrationResult result = rp.finishRegistration(registration);
            PublicKeyCredentialDescriptor id = result.getKeyId();
            ByteArray pubKeyCose = result.getPublicKeyCose();

            String serializedCredential = serializeNewCredential(name, id, pubKeyCose);
            CredentialWebAuthn credentialWebAuthn = new CredentialWebAuthn(serializedCredential);
            user.addCredential(credentialWebAuthn);
            session.delete();
            return credentialWebAuthn;
        } finally {
            userThreadLocal.remove();
        }
    }

    public String startLogin(User user) {
        try {
            userThreadLocal.set(user);

            CredentialSession session = getSession(false, true);

            AssertionRequest request;
            try {
                byte[] challenge = Util.unhex(session.getData());
                request = getAssertionRequest(challenge);
            } catch (NullPointerException e) {
                request = getAssertionRequest(null);
                session.setData(Util.hex(request.getPublicKeyCredentialRequestOptions().getChallenge().getBytes()));
            }
            try {
                return fixRequestJson(jsonMapper.writeValueAsString(request));
            } catch (JsonProcessingException jpe) {
                throw new RuntimeException(jpe);
            }
        } finally {
            userThreadLocal.remove();
        }
    }

    public CredentialWebAuthn finishLogin(User user, String json) {
        try {
            userThreadLocal.set(user);
            CredentialSession session = getSession(false, false);

            json = fixResultJson(json, true);

            AssertionRequest request;
            try {
                request = getAssertionRequest(Util.unhex(session.getData()));
            } catch (Exception e) {
                return null;
            }

            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc
                    = PublicKeyCredential.parseAssertionResponseJson(json);

            AssertionResult result = rp.finishAssertion(FinishAssertionOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build());

            if (result.isSuccess()) {
                session.delete();
                List<RegisteredCredentialData> data = retrieve(getUser().getUUID().toString());
                for (RegisteredCredentialData credential : data) {
                    if (credential.registeredCredential.getCredentialId().equals(result.getCredential().getCredentialId())) {
                        credential.credential.recordUse();
                        return credential.credential;
                    }
                }
            }
            return null;
        } catch (AssertionFailedException | IOException e) {
            return null;
        } finally {
            userThreadLocal.remove();
        }
    }

    private String fixRequestJson(String json) {
        // The browser side WebAuthn API requires the key to be publicKey
        // and not publicKeyCredentialRequestOptions
        JsonObject object = JsonParser.parseString(json).getAsJsonObject();
        if (object.has("publicKeyCredentialRequestOptions") && !object.has("publicKey")) {
            object.add("publicKey", object.get("publicKeyCredentialRequestOptions"));
            object.remove("publicKeyCredentialRequestOptions");
            return object.toString();
        } else {
            return json;
        }
    }

    private String fixResultJson(String json, boolean login) {
        JsonObject object = JsonParser.parseString(json).getAsJsonObject();
        boolean didAFix = false;
        if (!object.has("clientExtensionResults")) {
            // The Yubico WebAuthn API doesn't like clientExtensionResults being missing
            // so we just add it as an empty object if it's missing.
            object.add("clientExtensionResults", new JsonObject());
            didAFix = true;
        }
        if (login && object.has("response")) {
            // The Yubico WebAuthn API requires a userHandle in the response
            // The Ledger FIDO U2F app returns a response with a null
            // userHandle however.
            JsonElement response = object.get("response");
            if (response instanceof JsonObject) {
                JsonObject responseObject = (JsonObject) response;
                if (!responseObject.has("userHandle") || responseObject.get("userHandle").isJsonNull()) {
                    responseObject.addProperty("userHandle", Base64.getEncoder().encodeToString(getHandleBytes(getUser().getDisplayName())));
                }
            }
        }
        if (didAFix) {
            return object.toString();
        } else {
            return json;
        }
    }

    private String serializeNewCredential(String name, PublicKeyCredentialDescriptor id, ByteArray pubKeyCose) {
        RegisteredCredential rc = toRegisteredCredential(getHandle(name), id, pubKeyCose);
        return serialize(rc);
    }

    private List<RegisteredCredentialData> retrieve(String name) {
        List<RegisteredCredentialData> results = new ArrayList<>();
        if (!name.equals(getUser().getDisplayName())) {
            return results;
        }
        for (CredentialWebAuthn credential : getUser().getCredentials(CredentialWebAuthn.class)) {
            results.add(new RegisteredCredentialData(credential, deserialize(credential.key)));
        }
        return results;
    }

    private String serialize(RegisteredCredential rc) {
        return rc.getCredentialId().getHex() + "/" + rc.getPublicKeyCose().getHex() + "/" + rc.getUserHandle().getHex() + "/" + rc.getSignatureCount();
    }

    private RegisteredCredential deserialize(String string) {
        String[] split = string.split("/", 5);
        ByteArray credentialId = new ByteArray(Util.unhex(split[0]));
        ByteArray publicKeyCose = new ByteArray(Util.unhex(split[1]));
        ByteArray userHandle = new ByteArray(Util.unhex(split[2]));
        long signatureCount = Long.parseLong(split[3]);
        return RegisteredCredential.builder()
                .credentialId(credentialId)
                .userHandle(userHandle)
                .publicKeyCose(publicKeyCose)
                .signatureCount(signatureCount)
                .build();
    }

    private PublicKeyCredentialDescriptor toCredentialDescriptor(RegisteredCredential rc) {
        return PublicKeyCredentialDescriptor.builder()
                .id(rc.getCredentialId())
                .build();
    }

    private RegisteredCredential toRegisteredCredential(ByteArray userHandle, PublicKeyCredentialDescriptor pkcd, ByteArray pubKeyCose) {
        return RegisteredCredential.builder()
                .credentialId(pkcd.getId())
                .userHandle(userHandle)
                .publicKeyCose(pubKeyCose)
                .build();
    }

    private static class RegisteredCredentialData {
        private final CredentialWebAuthn credential;
        private final RegisteredCredential registeredCredential;

        public RegisteredCredentialData(CredentialWebAuthn credential, RegisteredCredential registeredCredential) {
            this.credential = credential;
            this.registeredCredential = registeredCredential;
        }
    }

    private class CR implements CredentialRepository {

        @Override
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
            HashSet<PublicKeyCredentialDescriptor> results = new HashSet<>();
            for (RegisteredCredentialData credential : retrieve(username)) {
                results.add(toCredentialDescriptor(credential.registeredCredential));
            }
            return results;
        }

        @Override
        public Optional<ByteArray> getUserHandleForUsername(String username) {
            return Optional.of(getHandle(username));
        }

        @Override
        public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
            return Optional.of(getName(userHandle));
        }

        @Override
        public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
            List<RegisteredCredentialData> credentials = retrieve(getName(userHandle));
            for (RegisteredCredentialData credential : credentials) {
                if (credential.registeredCredential.getCredentialId().equals(credentialId)) {
                    return Optional.of(credential.registeredCredential);
                }
            }
            return Optional.empty();
        }

        @Override
        public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
            return Collections.EMPTY_SET;
        }
    }
}
