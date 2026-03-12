package com.caleb.backend.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

/**
 * Infrastructure beans — no dependencies on other application beans.
 *
 * RSA Key Strategy:
 *   PRODUCTION : reads RSA_PRIVATE_KEY + RSA_PUBLIC_KEY from environment variables
 *                (base64-encoded DER format, generated once via generate-keys.sh)
 *   DEVELOPMENT: generates a fresh keypair on every restart (tokens invalidated on restart)
 *
 * The active profile is detected automatically:
 *   - if RSA_PRIVATE_KEY env var is set → use it (production)
 *   - otherwise → generate (development)
 */
@Configuration
public class AppConfig {

    private static final Logger log = LoggerFactory.getLogger(AppConfig.class);

    @Value("${RSA_PRIVATE_KEY:}")
    private String rsaPrivateKeyBase64;

    @Value("${RSA_PUBLIC_KEY:}")
    private String rsaPublicKeyBase64;

    // -------------------------------------------------------------------------
    // Password encoder
    // -------------------------------------------------------------------------

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // strength 12 for production
    }

    // -------------------------------------------------------------------------
    // JWK source
    // -------------------------------------------------------------------------

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = loadOrGenerateKeyPair();

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, ctx) -> jwkSelector.select(jwkSet);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private KeyPair loadOrGenerateKeyPair() {
        if (rsaPrivateKeyBase64 != null && !rsaPrivateKeyBase64.isBlank()
                && rsaPublicKeyBase64 != null && !rsaPublicKeyBase64.isBlank()) {
            log.info("[AppConfig] Loading RSA key pair from environment variables");
            return loadKeyPairFromEnv();
        }

        log.warn("[AppConfig] RSA_PRIVATE_KEY not set — generating ephemeral key pair. " +
                "Tokens will be invalidated on restart. Set RSA_PRIVATE_KEY and " +
                "RSA_PUBLIC_KEY environment variables for production.");
        return generateKeyPair();
    }

    private KeyPair loadKeyPairFromEnv() {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");

            byte[] privateBytes = Base64.getDecoder().decode(rsaPrivateKeyBase64.trim());
            byte[] publicBytes  = Base64.getDecoder().decode(rsaPublicKeyBase64.trim());

            RSAPrivateKey privateKey = (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
            RSAPublicKey  publicKey  = (RSAPublicKey)  kf.generatePublic(new X509EncodedKeySpec(publicBytes));

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA keys from environment variables. " +
                            "Ensure RSA_PRIVATE_KEY and RSA_PUBLIC_KEY are valid base64-encoded DER keys. " +
                            "Run scripts/generate-keys.sh to create them.", e);
        }
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("RSA key generation failed", e);
        }
    }
}