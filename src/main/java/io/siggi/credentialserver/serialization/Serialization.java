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
package io.siggi.credentialserver.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.siggi.credentialserver.credential.Credential;
import io.siggi.credentialserver.credential.CredentialType;
import io.siggi.credentialserver.util.Util;

import java.io.IOException;
import java.util.UUID;

public final class Serialization {
    private static final Gson gson;
    private static final Gson gsonPretty;

    static {
        GsonBuilder builder = new GsonBuilder();
        TypeAdapter<Credential> credentialAdapter = new TypeAdapter<Credential>() {
            @Override
            public Credential read(JsonReader reader) throws IOException {
                JsonObject object = JsonParser.parseReader(reader).getAsJsonObject();
                String type = object.get("type").getAsString();
                String uuidString = object.get("uuid").getAsString();
                String name;
                try {
                    name = object.get("name").getAsString();
                } catch (Exception e) {
                    name = null;
                }
                UUID uuid = Util.uuidFromString(uuidString);
                String data = object.get("data").getAsString();
                long useCount = object.get("useCount").getAsLong();
                long lastUse = object.get("lastUse").getAsLong();
                long expires = object.get("expires").getAsLong();
                CredentialType<?> credentialType = CredentialType.get(type);
                if (credentialType == null)
                    return null;
                return credentialType.deserialize(data, uuid, name, useCount, lastUse, expires);
            }

            @Override
            public void write(JsonWriter writer, Credential o) throws IOException {
                writer.beginObject();
                writer.name("type").value(o.getType());
                writer.name("uuid").value(o.getUUID().toString());
                writer.name("name").value(o.getName());
                writer.name("data").value(o.getData());
                writer.name("useCount").value(o.getUseCount());
                writer.name("lastUse").value(o.getLastUse());
                writer.name("expires").value(o.getExpires());
                writer.endObject();
            }
        };
        builder.registerTypeAdapter(Credential.class, credentialAdapter);
        for (CredentialType<?> type : CredentialType.getTypes().values()) {
            builder.registerTypeAdapter(type.getTypeClass(), credentialAdapter);
        }
        gson = builder.create();
        builder.setPrettyPrinting();
        gsonPretty = builder.create();
    }

    private Serialization() {
    }

    public static String serialize(Object object, boolean pretty) {
        return (pretty ? gsonPretty : gson).toJson(object);
    }

    public static <T> T deserialize(String json, Class<T> type) {
        return gson.fromJson(json, type);
    }
}
