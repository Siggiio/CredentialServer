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
package io.siggi.credentialserver.apiresponses;

public class ExceptionInfo {
    public transient Throwable throwable;
    public boolean success;
    public String exception;
    public String message;

    public ExceptionInfo() {
    }

    public ExceptionInfo(Throwable throwable) {
        this.throwable = throwable;
        success = false;
        exception = throwable.getClass().getName();
        message = throwable.getMessage();
    }

    public ExceptionInfo(String message) {
        success = false;
        this.message = message;
    }
}
