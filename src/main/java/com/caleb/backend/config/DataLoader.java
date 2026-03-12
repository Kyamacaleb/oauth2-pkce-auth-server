package com.caleb.backend.config;

import com.caleb.backend.model.User;
import com.caleb.backend.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

/**
 * Startup seeder.
 *
 * OAuth client:
 *   Always seeds the frontend-app client if it doesn't exist.
 *   REDIRECT_URI is configurable via APP_BASE_URL env var so Docker / cloud
 *   deployments don't need to change code.
 *
 * Default user:
 *   Only seeded when SEED_DEFAULT_USER=true (dev convenience).
 *   NEVER printed to logs — credentials come from environment variables.
 *   In production leave SEED_DEFAULT_USER unset (defaults to false).
 */
@Component
public class DataLoader implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataLoader.class);

    private static final String CLIENT_ID = "frontend-app";

    @Value("${app.base-url:http://localhost:8080}")
    private String appBaseUrl;

    @Value("${SEED_DEFAULT_USER:false}")
    private boolean seedDefaultUser;

    @Value("${DEFAULT_USER_EMAIL:user@example.com}")
    private String defaultUserEmail;

    @Value("${DEFAULT_USER_PASSWORD:}")
    private String defaultUserPassword;

    private final UserRepository             userRepository;
    private final PasswordEncoder            passwordEncoder;
    private final RegisteredClientRepository clientRepository;

    public DataLoader(UserRepository userRepository,
                      PasswordEncoder passwordEncoder,
                      RegisteredClientRepository clientRepository) {
        this.userRepository   = userRepository;
        this.passwordEncoder  = passwordEncoder;
        this.clientRepository = clientRepository;
    }

    @Override
    public void run(String... args) {
        seedOAuthClient();
        if (seedDefaultUser) {
            seedUser();
        }
    }

    // -------------------------------------------------------------------------
    // OAuth2 client
    // -------------------------------------------------------------------------

    private void seedOAuthClient() {
        if (clientRepository.findByClientId(CLIENT_ID) != null) {
            log.info("[DataLoader] OAuth client '{}' already registered — skipping", CLIENT_ID);
            return;
        }

        String redirectUri = appBaseUrl + "/callback";

        RegisteredClient client = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientName("Frontend App")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectUri)
                .scope("openid")
                .scope("read:profile")
                .scope("read:email")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
                .build();

        clientRepository.save(client);
        log.info("[DataLoader] OAuth client '{}' registered with redirect: {}", CLIENT_ID, redirectUri);
    }

    // -------------------------------------------------------------------------
    // Default user (dev only)
    // -------------------------------------------------------------------------

    private void seedUser() {
        if (defaultUserPassword == null || defaultUserPassword.isBlank()) {
            log.warn("[DataLoader] SEED_DEFAULT_USER=true but DEFAULT_USER_PASSWORD is not set — skipping user seed");
            return;
        }

        if (userRepository.existsByEmail(defaultUserEmail)) {
            log.info("[DataLoader] Default user '{}' already exists — skipping", defaultUserEmail);
            return;
        }

        User user = new User();
        user.setEmail(defaultUserEmail);
        user.setPassword(passwordEncoder.encode(defaultUserPassword));
        user.setFullName("Default User");
        user.setEnabled(true);
        userRepository.save(user);

        // Intentionally NOT logging the password
        log.info("[DataLoader] Default user '{}' created", defaultUserEmail);
    }
}