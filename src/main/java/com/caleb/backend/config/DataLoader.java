package com.caleb.backend.config;

import com.caleb.backend.model.User;
import com.caleb.backend.repository.UserRepository;
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
 * Seeds the database on startup:
 * No manual curl needed — the app is fully ready to use immediately.
 */
@Component
public class DataLoader implements CommandLineRunner {

    private static final String DEFAULT_EMAIL    = "user@example.com";
    private static final String DEFAULT_PASSWORD = "Password123!";
    private static final String CLIENT_ID        = "frontend-app";
    private static final String REDIRECT_URI     = "http://localhost:8080/callback";

    private final UserRepository           userRepository;
    private final PasswordEncoder          passwordEncoder;
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
        seedUser();
        seedOAuthClient();
    }

    // User
    private void seedUser() {
        if (userRepository.existsByEmail(DEFAULT_EMAIL)) {
            return;
        }
        User user = new User();
        user.setEmail(DEFAULT_EMAIL);
        user.setPassword(passwordEncoder.encode(DEFAULT_PASSWORD));
        user.setFullName("Default User");
        user.setEnabled(true);
        userRepository.save(user);
    }

    // OAuth2 client
    private void seedOAuthClient() {
        if (clientRepository.findByClientId(CLIENT_ID) != null) {
            return; // already registered
        }

        RegisteredClient client = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientName("Frontend App")
                // Public client — no secret, PKCE required
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(REDIRECT_URI)
                .scope("openid")
                .scope("read:profile")
                .scope("read:email")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)   // skip consent screen
                        .requireProofKey(true)                // enforce PKCE
                        .build())
                .build();

        clientRepository.save(client);
    }
}