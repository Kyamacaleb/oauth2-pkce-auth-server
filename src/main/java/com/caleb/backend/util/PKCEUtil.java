package com.caleb.backend.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility for generating PKCE (RFC 7636) code verifier and S256 challenge.
 * Used server-side — the verifier is stored in the HTTP session and sent
 * when exchanging the authorization code for a token.
 */
public final class PKCEUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PKCEUtil() {}

    /**
     * Generates a cryptographically random code verifier (43–128 chars, URL-safe).
     */
    public static String generateCodeVerifier() {
        byte[] bytes = new byte[32]; // 32 bytes → 43-char base64url string
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Derives the S256 code challenge from the verifier.
     * challenge = BASE64URL(SHA-256(ASCII(verifier)))
     */
    public static String generateCodeChallenge(String codeVerifier) {
        try {
            byte[] bytes  = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}