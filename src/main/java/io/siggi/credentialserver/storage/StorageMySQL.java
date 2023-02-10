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

import io.siggi.credentialserver.credential.Credential;
import io.siggi.credentialserver.credential.CredentialSession;
import io.siggi.credentialserver.credential.CredentialType;
import io.siggi.credentialserver.credential.User;
import io.siggi.credentialserver.util.Util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;
import java.util.UUID;

public class StorageMySQL extends Storage {

    private final String server;
    private final String database;
    private final String username;
    private final String password;

    public StorageMySQL(Properties configuration) {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("MySQL Driver not available", e);
        }
        String server = configuration.getProperty("mysql-server");
        if (!server.substring(server.indexOf("]") + 1).contains(":")) server += ":3306";
        this.server = server;
        database = configuration.getProperty("mysql-database");
        username = configuration.getProperty("mysql-username");
        password = configuration.getProperty("mysql-password");
        try (Connection connection = getConnection()) {
            try (PreparedStatement createCredentialsTable = connection.prepareStatement(
                    "CREATE TABLE IF NOT EXISTS `usercredentials` (" +
                            "`credentialid` binary(16) NOT NULL," +
                            "`userid` binary(16) NOT NULL," +
                            "`type` varchar(16) NOT NULL," +
                            "`data` varchar(1024) NOT NULL," +
                            "`name` varchar(64) NULL," +
                            "`usecount` bigint NOT NULL DEFAULT '0'," +
                            "`lastuse` bigint NOT NULL DEFAULT '0'," +
                            "`expires` bigint NOT NULL DEFAULT '0'," +
                            "PRIMARY KEY (`credentialid`)," +
                            "KEY `userid` (`userid`)" +
                            ")"
            )) {
                createCredentialsTable.executeUpdate();
            }
            try (PreparedStatement createUserDataTable = connection.prepareStatement(
                    "CREATE TABLE IF NOT EXISTS `userdata` (" +
                            "`userid` binary(16) NOT NULL," +
                            "`variable` varchar(32) NOT NULL," +
                            "`value` varchar(64) NOT NULL," +
                            "UNIQUE KEY `uservariable` (`userid`,`variable`)" +
                            ")"
            )) {
                createUserDataTable.executeUpdate();
            }
            try (PreparedStatement createCredentialRegistrationSessions = connection.prepareStatement(
                    "CREATE TABLE IF NOT EXISTS `usercredentialsessions` (" +
                            "`userid` binary(16) NOT NULL," +
                            "`type` varchar(16) NOT NULL," +
                            "`registration` tinyint(1) NOT NULL," +
                            "`data` varchar(1024) NOT NULL," +
                            "`time` bigint NOT NULL," +
                            "`expiry` bigint NOT NULL," +
                            "PRIMARY KEY (`userid`,`type`,`registration`)" +
                            ")"
            )) {
                createCredentialRegistrationSessions.executeUpdate();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Could not create tables");
        }
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://" + server + "/" + database, username, password);
    }

    @Override
    public User readUser(UUID uuid) throws StorageException {
        try (Connection connection = getConnection()) {
            try (PreparedStatement credentialReader = connection.prepareStatement("SELECT * FROM `usercredentials` WHERE `userid`=?");
                 PreparedStatement dataReader = connection.prepareStatement("SELECT * FROM `userdata` WHERE `userid`=?");
                 PreparedStatement credentialSessionReader = connection.prepareStatement("SELECT * FROM `usercredentialsessions` WHERE `userid`=?")) {
                User user = new User();
                credentialReader.setBytes(1, Util.unhex(Util.uuidToString(uuid)));
                try (ResultSet resultSet = credentialReader.executeQuery()) {
                    while (resultSet.next()) {
                        UUID credentialId = Util.uuidFromString(Util.hex(resultSet.getBytes("credentialid")));
                        String type = resultSet.getString("type");
                        String data = resultSet.getString("data");
                        String name = resultSet.getString("name");
                        long useCount = resultSet.getLong("usecount");
                        long lastUse = resultSet.getLong("lastuse");
                        long expires = resultSet.getLong("expires");
                        user.addCredential(CredentialType.get(type).deserialize(data, credentialId, name, useCount, lastUse, expires));
                    }
                }
                dataReader.setBytes(1, Util.unhex(Util.uuidToString(uuid)));
                try (ResultSet resultSet = dataReader.executeQuery()) {
                    while (resultSet.next()) {
                        String variable = resultSet.getString("variable");
                        String value = resultSet.getString("value");
                        user.setVariable(variable, value);
                    }
                }
                credentialSessionReader.setBytes(1, Util.unhex(Util.uuidToString(uuid)));
                try (ResultSet resultSet = credentialSessionReader.executeQuery()) {
                    while (resultSet.next()) {
                        String type = resultSet.getString("type");
                        boolean registration = resultSet.getBoolean("registration");
                        String data = resultSet.getString("data");
                        long time = resultSet.getLong("time");
                        long expiry = resultSet.getLong("expiry");
                        CredentialSession credentialSession = new CredentialSession(type, registration, data, time, expiry);
                        user.getCredentialSessionsMap().put(type + "-" + registration, credentialSession);
                    }
                }
                return user;
            }
        } catch (SQLException ex) {
            throw new StorageException("Database access", ex);
        }
    }

    @Override
    public void saveUser(UUID uuid, User user) throws StorageException {
        long now = System.currentTimeMillis();
        try (Connection connection = getConnection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement insertCredential = connection.prepareStatement(
                    "INSERT INTO `usercredentials` (`credentialid`,`userid`,`type`,`data`,`name`,`usecount`,`lastuse`,`expires`) "
                            + "VALUES (?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE `data`=?,`name`=?,`usecount`=?,`lastuse`=?,`expires`=?"
            ); PreparedStatement deleteCredential = connection.prepareStatement(
                    "DELETE FROM `usercredentials` WHERE `credentialid`=?"
            )) {
                insertCredential.setBytes(2, Util.unhex(Util.uuidToString(uuid)));
                for (Credential credential : user.getCredentials()) {
                    if (credential.isDeleted() || (credential.getExpires() > 0L && credential.getExpires() < now)) {
                        deleteCredential.setBytes(1, Util.unhex(credential.getUUID().toString().replace("-", "")));
                        deleteCredential.addBatch();
                        continue;
                    }
                    if (!credential.hasChanged()) continue;
                    insertCredential.setBytes(1, Util.unhex(credential.getUUID().toString().replace("-", "")));
                    insertCredential.setString(3, credential.getType());
                    insertCredential.setString(4, credential.getData());
                    insertCredential.setString(5, credential.getName());
                    insertCredential.setLong(6, credential.getUseCount());
                    insertCredential.setLong(7, credential.getLastUse());
                    insertCredential.setLong(8, credential.getExpires());

                    insertCredential.setString(9, credential.getData());
                    insertCredential.setString(10, credential.getName());
                    insertCredential.setLong(11, credential.getUseCount());
                    insertCredential.setLong(12, credential.getLastUse());
                    insertCredential.setLong(13, credential.getExpires());
                    insertCredential.addBatch();
                }
                insertCredential.executeBatch();
                deleteCredential.executeBatch();
            }
            try (PreparedStatement setVariable = connection.prepareStatement(
                    "INSERT INTO `userdata` (`userid`,`variable`,`value`) VALUES (?,?,?) "
                            + "ON DUPLICATE KEY UPDATE `value`=?"
            ); PreparedStatement deleteVariable = connection.prepareStatement(
                    "DELETE FROM `userdata` WHERE `userid`=? AND `variable`=?"
            )) {
                setVariable.setBytes(1, Util.unhex(Util.uuidToString(uuid)));
                deleteVariable.setBytes(1, Util.unhex(Util.uuidToString(uuid)));
                for (String variable : user.getChangedVariables()) {
                    String value = user.getVariable(variable);
                    if (value == null) {
                        deleteVariable.setString(2, variable);
                        deleteVariable.addBatch();
                    } else {
                        setVariable.setString(2, variable);
                        setVariable.setString(3, value);
                        setVariable.setString(4, value);
                        setVariable.addBatch();
                    }
                }
                setVariable.executeBatch();
                deleteVariable.executeBatch();
                user.getChangedVariables().clear();
            }
            try (PreparedStatement insertCredentialSession = connection.prepareStatement(
                    "INSERT INTO `usercredentialsessions` (`userid`,`type`,`registration`,`data`,`time`,`expiry`) VALUES (?,?,?,?,?,?) "
                            + "ON DUPLICATE KEY UPDATE `data`=?, `time`=?, `expiry`=?"
            ); PreparedStatement deleteCredentialSession = connection.prepareStatement(
                    "DELETE FROM `usercredentialsessions` WHERE `userid`=? AND `type`=? AND `registration`=?"
            )) {
                insertCredentialSession.setBytes(1, Util.unhex(Util.uuidToString(uuid)));
                deleteCredentialSession.setBytes(1, Util.unhex(Util.uuidToString(uuid)));
                for (CredentialSession session : user.getCredentialSessions()) {
                    if (session.isDeleted() || session.getExpiry() < now) {
                        deleteCredentialSession.setString(2, session.getType());
                        deleteCredentialSession.setBoolean(3, session.isRegistration());
                        deleteCredentialSession.addBatch();
                        continue;
                    }
                    if (!session.hasChanged()) continue;
                    insertCredentialSession.setString(2, session.getType());
                    insertCredentialSession.setBoolean(3, session.isRegistration());
                    insertCredentialSession.setString(4, session.getData());
                    insertCredentialSession.setLong(5, session.getTime());
                    insertCredentialSession.setLong(6, session.getExpiry());

                    insertCredentialSession.setString(7, session.getData());
                    insertCredentialSession.setLong(8, session.getTime());
                    insertCredentialSession.setLong(9, session.getExpiry());

                    insertCredentialSession.addBatch();
                }
                insertCredentialSession.executeBatch();
                deleteCredentialSession.executeBatch();
            }
            connection.commit();
        } catch (SQLException ex) {
            throw new StorageException("Database access", ex);
        }
    }
}
