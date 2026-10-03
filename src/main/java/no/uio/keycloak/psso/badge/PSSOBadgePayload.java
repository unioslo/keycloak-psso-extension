/* Copyright 2025 University of Oslo, Norway
 # This file is part of the Keycloak Platform SSO Extension codebase.
 #
 # This extension for Keycloak is free software; you can redistribute
 # it and/or modify it under the terms of the GNU General Public License
 # as published by the Free Software Foundation;
 # either version 2 of the License, or (at your option) any later version.
 #
 # This extension is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this extension; if not, write to the Free Software Foundation,
 # Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
*/

package no.uio.keycloak.psso.badge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.util.JsonSerialization;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * What is actually printed on a pupil's lanyard badge:
 *
 * <pre>PSSO1.&lt;base64url( {"u":"&lt;user id&gt;","s":&lt;sequence&gt;,"t":"&lt;token&gt;"} )&gt;</pre>
 *
 * <p>The badge is a <em>first</em> factor, so the server has to find the user from the payload
 * alone — there is no user yet to look credentials up against. Hence the user id in the
 * payload. It is the Keycloak user id and not the username on purpose: it is already the
 * indexed primary key, and a badge that falls on the floor does not announce whose it is.
 *
 * <p>The token is 12 random bytes. At 96 bits, stretching the hash buys nothing that the
 * entropy does not already give, so it is stored as a plain SHA-256 and compared in constant
 * time.
 *
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PSSOBadgePayload {

    /**
     * Version prefix. Lets the scanner reject an unrelated QR code (a cereal box, a bus
     * ticket) with a clear message instead of posting garbage at the login endpoint, and
     * leaves room to change the format later.
     */
    public static final String PREFIX = "PSSO1.";

    /** 96 bits. Comparable to a random 15-character password with symbols. */
    private static final int TOKEN_BYTES = 12;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DECODER = Base64.getUrlDecoder();

    private String userId;
    private int sequence;
    private String token;

    public PSSOBadgePayload() {
    }

    public PSSOBadgePayload(String userId, int sequence, String token) {
        this.userId = userId;
        this.sequence = sequence;
        this.token = token;
    }

    /**
     * Generates the secret half of a new badge. The caller stores only {@link #hashToken} of
     * this and hands the plaintext back to the issuer exactly once.
     */
    public static String newToken() {
        byte[] raw = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(raw);
        return B64URL.encodeToString(raw);
    }

    public static byte[] sha256(String token) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            // Every conforming JRE ships SHA-256; if it is missing something is very wrong.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String hashToken(String token) {
        return Base64.getEncoder().encodeToString(sha256(token));
    }

    /** Renders the string that goes into the printed QR code. */
    public String encode() {
        try {
            return PREFIX + B64URL.encodeToString(JsonSerialization.writeValueAsBytes(this));
        } catch (Exception e) {
            throw new RuntimeException("Error serializing badge payload", e);
        }
    }

    /**
     * Parses a scanned payload, or returns {@code null} if it is not one of ours.
     *
     * <p>Malformed input is the normal case here, not an exceptional one — people scan the
     * wrong thing — so this reports it as a value rather than by throwing.
     */
    public static PSSOBadgePayload parse(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        if (!trimmed.startsWith(PREFIX)) {
            return null;
        }
        try {
            byte[] json = B64URL_DECODER.decode(trimmed.substring(PREFIX.length()));
            PSSOBadgePayload payload = JsonSerialization.readValue(json, PSSOBadgePayload.class);
            if (payload == null
                    || payload.userId == null || payload.userId.isBlank()
                    || payload.token == null || payload.token.isBlank()) {
                return null;
            }
            return payload;
        } catch (Exception e) {
            return null;
        }
    }

    @JsonProperty("u")
    public String getUserId() {
        return userId;
    }

    @JsonProperty("u")
    public void setUserId(String userId) {
        this.userId = userId;
    }

    @JsonProperty("s")
    public int getSequence() {
        return sequence;
    }

    @JsonProperty("s")
    public void setSequence(int sequence) {
        this.sequence = sequence;
    }

    @JsonProperty("t")
    public String getToken() {
        return token;
    }

    @JsonProperty("t")
    public void setToken(String token) {
        this.token = token;
    }
}
