package com.caleb.backend.service;

import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Service
public class PKCEService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generate a code verifier for PKCE
     * Code verifier is a high-entropy cryptographic random string
     */
    public String generateCodeVerifier() {
        byte[] codeVerifier = new byte[32];
        SECURE_RANDOM.nextBytes(codeVerifier);
        return Base64.encodeBase64URLSafeString(codeVerifier);
    }

    /**
     * Generate code challenge from verifier using S256 method
     * challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
     */
    public String generateCodeChallengeS256(String codeVerifier) {
        try {
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes, 0, bytes.length);
            byte[] digest = messageDigest.digest();
            return Base64.encodeBase64URLSafeString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Verify PKCE challenge
     */
    public boolean verifyPKCE(String codeVerifier, String codeChallenge, String method) {
        if (codeVerifier == null || codeChallenge == null || method == null) {
            return false;
        }

        if ("S256".equals(method)) {
            String computedChallenge = generateCodeChallengeS256(codeVerifier);
            return computedChallenge.equals(codeChallenge);
        } else if ("plain".equals(method)) {
            return codeVerifier.equals(codeChallenge);
        }

        return false;
    }
}