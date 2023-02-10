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
package io.siggi.credentialserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.siggi.credentialserver.apiresponses.ClientsideCredential;
import io.siggi.credentialserver.apiresponses.ExceptionInfo;
import io.siggi.credentialserver.apiresponses.LoginResult;
import io.siggi.credentialserver.apiresponses.StartLogin;
import io.siggi.credentialserver.apiresponses.Success;
import io.siggi.credentialserver.credential.Credential;
import io.siggi.credentialserver.credential.CredentialType;
import io.siggi.credentialserver.credential.User;
import io.siggi.credentialserver.credential.UserNamespace;
import io.siggi.credentialserver.serialization.Serialization;
import io.siggi.credentialserver.storage.StorageException;
import io.siggi.credentialserver.util.Util;
import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPServer;
import io.siggi.http.HTTPServerBuilder;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;

public final class CredentialServer {

    public final File tmpDirectory;
    private final File root;
    private final File namespacesDirectory;
    private final File webRoot;
    private final String listenIP;
    private final int listenPort;
    private final Map<String, UserNamespace> namespaces = new HashMap<>();
    private ServerSocket serverSocket;
    private HTTPServer server;

    public CredentialServer(String listenIP, int listenPort, File root) {
        this.listenIP = listenIP;
        this.listenPort = listenPort;
        this.root = root;
        this.namespacesDirectory = new File(root, "namespaces");
        this.tmpDirectory = new File(root, "tmp");
        if (tmpDirectory.exists())
            for (File f : this.tmpDirectory.listFiles()) {
                f.delete();
            }
        else
            tmpDirectory.mkdirs();
        File[] namespaceDirectories = namespacesDirectory.listFiles();
        if (namespaceDirectories != null) {
            for (File namespaceDir : namespaceDirectories) {
                String namespace = namespaceDir.getName();
                File configFile = new File(namespaceDir, "config.txt");
                if (!configFile.exists()) continue;
                namespaces.put(namespace, new UserNamespace(this, namespace, namespaceDir));
            }
        }
        File webRoot = new File(root, "webroot");
        if (webRoot.isDirectory()) {
            this.webRoot = webRoot;
        } else {
            this.webRoot = null;
        }
    }

    private static void writeResponse(HTTPRequest request, String data, String contentType) throws IOException {
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        request.response.setContentType(contentType);
        request.response.contentLength(dataBytes.length);
        request.response.write(dataBytes);
    }

    private static void writeJsonResponse(HTTPRequest request, Object data) throws IOException {
        boolean pretty = request.get.get("pretty") != null;
        String serialized = Serialization.serialize(data, pretty);
        writeResponse(request, serialized, "application/json");
    }

    public static void main(String[] args) throws IOException {
        String listen = System.getProperty("credentialserverport", "8080");
        String listenIP;
        int listenPort;
        int colonPos = listen.lastIndexOf(":");
        if (colonPos == -1) {
            listenIP = null;
            listenPort = Integer.parseInt(listen);
        } else {
            listenIP = listen.substring(0, colonPos);
            listenPort = Integer.parseInt(listen.substring(colonPos + 1));
        }
        String root = System.getProperty("credentialserverdatadir");
        if (root == null) root = "data";
        File rootFile = new File(root);
        CredentialServer credentialServer = new CredentialServer(listenIP, listenPort, rootFile);
        credentialServer.start();
    }

    public void start() throws IOException {
        if (serverSocket != null)
            throw new IllegalStateException("Already started!");
        serverSocket = new ServerSocket(listenPort, 0, listenIP == null ? null : InetAddress.getByName(listenIP));
        server = new HTTPServerBuilder().build();
        server.responderRegistry.register("/", this::respond, true, true);
        new Thread(() -> {
            try {
                while (true) {
                    Socket socket = serverSocket.accept();
                    server.handle(socket);
                }
            } catch (Exception e) {
            }
        }).start();
    }

    public void stop() {
        if (serverSocket == null)
            throw new IllegalStateException("Never started!");
        try {
            serverSocket.close();
        } catch (Exception e) {
        }
    }

    private void respond(HTTPRequest request) throws IOException {
        try {
            if (webRoot != null && !request.url.contains("..")) {
                File requestedFile = new File(webRoot, request.url.substring(1));
                if (requestedFile.exists()) {
                    if (requestedFile.isDirectory()) {
                        File indexFile = new File(requestedFile, "index.html");
                        if (indexFile.exists()) {
                            request.response.redirect(request.url + (request.url.endsWith("/") ? "" : "/") + "index.html");
                        }
                        return;
                    }
                    request.response.returnFile(requestedFile);
                    return;
                }
            }
            String topDirectory;
            String subpath;
            int slashPosition = request.url.indexOf("/", 1);
            if (slashPosition == -1) {
                topDirectory = request.url.substring(1);
                subpath = null;
            } else {
                topDirectory = request.url.substring(1, slashPosition);
                subpath = request.url.substring(slashPosition + 1);
            }
            switch (topDirectory) {
                case "users": {
                    if (subpath == null)
                        break;
                    String[] parts = subpath.split("/", 3);
                    if (parts.length < 3)
                        break;
                    String namespace = parts[0];
                    String user = parts[1];
                    String action = parts[2];
                    respondToUsers(request, namespace, user, action);
                }
                break;
            }
        } catch (Exception e) {
            writeJsonResponse(request, new ExceptionInfo(e));
            e.printStackTrace();
        }
    }

    private void respondToUsers(HTTPRequest request, String namespace, String userId, String action) throws StorageException, IOException {
        UUID userUuid;
        try {
            userUuid = Util.uuidFromString(userId);
        } catch (Exception e) {
            // the user string was not a UUID
            userUuid = UUID.nameUUIDFromBytes((namespace + ":" + userId).getBytes(StandardCharsets.UTF_8));
        }
        if (userId.isEmpty()) {
            writeJsonResponse(request, new ExceptionInfo("User is blank"));
            return;
        }
        UserNamespace userNamespace = getNamespace(namespace);
        User user = userNamespace.readUser(userUuid);
        JsonObject postData;
        // <editor-fold desc="Parse POST data" defaultstate="collapsed">
        if (request.method.equals("POST")) {
            String contentType = request.getHeader("Content-Type");
            if (contentType != null && contentType.contains("json")) {
                String contentLengthStr = request.getHeader("Content-Length");
                if (contentLengthStr == null) {
                    request.response.setHeader("400 Bad Request");
                    request.response.sendHeaders();
                    return;
                }
                int contentLength = Integer.parseInt(contentLengthStr);
                if (contentLength > 65536) {
                    request.response.setHeader("413 Payload Too Large");
                    request.response.sendHeaders();
                    return;
                }
                postData = JsonParser.parseReader(new InputStreamReader(request.inStream)).getAsJsonObject();
            } else {
                postData = new JsonObject();
                for (Map.Entry<String, String> entry : request.post.entrySet()) {
                    postData.addProperty(entry.getKey(), entry.getValue());
                }
            }
        } else {
            postData = null;
        }
        // </editor-fold>
        switch (action) {
            case "types": {
                Set<String> credentialTypes = new HashSet<>();
                for (Credential credential : user.getCredentials()) {
                    credentialTypes.add(credential.getType());
                }
                writeJsonResponse(request, credentialTypes);
            }
            break;
            case "credentials": {
                Set<ClientsideCredential> credentials = new HashSet<>();
                for (Credential credential : user.getCredentials()) {
                    credentials.add(new ClientsideCredential(credential));
                }
                writeJsonResponse(request, credentials);
            }
            break;
            case "startregistration":
            case "startlogin": {
                if (postData == null)
                    break;
                boolean isRegistration = action.equals("startregistration");
                String type = postData.get("type").getAsString();
                CredentialType credentialType = CredentialType.get(type);
                if (!isRegistration && user.getCredentials(type).isEmpty()) {
                    writeJsonResponse(request, new ExceptionInfo("No credential of type '" + type + "' available."));
                    break;
                }
                String callResult = isRegistration
                        ? credentialType.startRegistration(user)
                        : credentialType.startLogin(user);
                writeJsonResponse(request, new StartLogin(callResult));
            }
            break;
            case "finishregistration":
            case "finishlogin": {
                if (postData == null)
                    break;
                boolean isRegistration = action.equals("finishregistration");
                String type = postData.get("type").getAsString();
                JsonElement dataJson = postData.get("data");
                String data;
                if (dataJson.isJsonPrimitive()) {
                    data = dataJson.getAsString();
                } else {
                    data = Serialization.serialize(dataJson, false);
                }
                CredentialType credentialType = CredentialType.get(type);
                if (credentialType == null) {
                    writeJsonResponse(request, new LoginResult(false, null));
                    break;
                }
                Credential credential = isRegistration
                        ? credentialType.finishRegistration(user, data)
                        : credentialType.finishLogin(user, data);
                if (credential != null) {
                    if (isRegistration) {
                        JsonElement nameElement = postData.get("name");
                        if (nameElement != null && !nameElement.isJsonNull()) {
                            credential.setName(nameElement.getAsString());
                        }
                    }
                    writeJsonResponse(request, new LoginResult(true, credential.getUUID()));
                } else {
                    writeJsonResponse(request, new LoginResult(false, null));
                }
            }
            break;
            case "rename": {
                String credentialId = postData.get("credential").getAsString();
                JsonElement nameElement = postData.get("name");
                String name = nameElement.isJsonNull() ? null : nameElement.getAsString();
                Credential credential = user.getCredential(Util.uuidFromString(credentialId));
                credential.setName(name);
                writeJsonResponse(request, new Success(true));
            }
            break;
            case "delete": {
                String credentialId = postData.get("credential").getAsString();
                Credential credential = user.getCredential(Util.uuidFromString(credentialId));
                if (credential == null) {
                    writeJsonResponse(request, new Success(false));
                    break;
                }
                credential.delete();
                writeJsonResponse(request, new Success(true));
            }
            break;
            case "metaset": {
                for (String key : postData.keySet()) {
                    JsonElement jsonValue = postData.get(key);
                    String value = jsonValue.isJsonNull() ? null : jsonValue.getAsString();
                    user.setVariable(key, value);
                }
                writeJsonResponse(request, new Success(true));
            }
            break;
            case "metaget": {
                JsonObject response = new JsonObject();
                Predicate<String> predicate = s -> true;
                if (postData != null && postData.has("keys")) {
                    JsonArray keys = postData.get("keys").getAsJsonArray();
                    HashSet<String> keysSet = new HashSet<>();
                    keys.forEach(s -> keysSet.add(s.getAsString()));
                    predicate = keysSet::contains;
                }
                for (Map.Entry<String, String> entry : user.getVariables().entrySet()) {
                    if (!predicate.test(entry.getKey()))
                        continue;
                    response.addProperty(entry.getKey(), entry.getValue());
                }
                writeJsonResponse(request, response);
            }
            break;
        }
        userNamespace.saveUser(user);
    }

    private UserNamespace getNamespace(String namespace) {
        return namespaces.get(namespace);
    }

}
