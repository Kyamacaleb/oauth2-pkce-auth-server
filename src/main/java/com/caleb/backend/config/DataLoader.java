package com.caleb.backend.config;

import com.caleb.backend.model.OAuthClient;
import com.caleb.backend.model.User;
import com.caleb.backend.repository.OAuthClientRepository;
import com.caleb.backend.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements CommandLineRunner {

    private final UserRepository userRepository;
    private final OAuthClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    public DataLoader(
            UserRepository userRepository,
            OAuthClientRepository clientRepository,
            PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        // Create test user if not exists
        if (!userRepository.existsByUsername("testuser")) {
            User user = new User();
            user.setUsername("testuser");
            user.setPassword(passwordEncoder.encode("password123"));
            user.setEmail("test@example.com");
            user.setFullName("Test User");
            user.setEnabled(true);
            userRepository.save(user);
            System.out.println("Created test user: testuser/password123");
        }

        // Create mobile app client (public client with PKCE)
        if (!clientRepository.existsByClientId("mobile-app-client")) {
            OAuthClient mobileClient = createMobileClient();
            clientRepository.save(mobileClient);
            System.out.println("Created mobile client: mobile-app-client");
        }

        // Create web app client (confidential client)
        if (!clientRepository.existsByClientId("web-app-client")) {
            OAuthClient webClient = createWebClient();
            clientRepository.save(webClient);
            System.out.println("Created web client: web-app-client");
        }
    }

    private OAuthClient createMobileClient() {
        OAuthClient mobileClient = new OAuthClient();
        mobileClient.setClientId("mobile-app-client");
        mobileClient.setClientSecret(null); // Public client - no secret
        mobileClient.setClientName("Mobile App");
        mobileClient.setRedirectUris(new String[]{
                "http://localhost:8080/callback",
                "http://localhost:8080/login/oauth2/code/mobile",
                "myapp://callback"
        });
        mobileClient.setGrantTypes(new String[]{
                "authorization_code",
                "refresh_token"
        });
        mobileClient.setScopes(new String[]{
                "read:profile",
                "read:email",
                "openid"
        });
        mobileClient.setClientType(OAuthClient.ClientType.PUBLIC);
        mobileClient.setAccessTokenValidity(3600); // 1 hour
        mobileClient.setRefreshTokenValidity(2592000); // 30 days
        return mobileClient;
    }

    private OAuthClient createWebClient() {
        OAuthClient webClient = new OAuthClient();
        webClient.setClientId("web-app-client");
        webClient.setClientSecret(passwordEncoder.encode("web-secret"));
        webClient.setClientName("Web Application");
        webClient.setRedirectUris(new String[]{
                "http://localhost:3000/callback",
                "http://localhost:8080/callback",
                "http://localhost:8080/login/oauth2/code/web"
        });
        webClient.setGrantTypes(new String[]{
                "authorization_code",
                "refresh_token",
                "client_credentials"
        });
        webClient.setScopes(new String[]{
                "read:profile",
                "read:email",
                "write:posts",
                "openid",
                "profile"
        });
        webClient.setClientType(OAuthClient.ClientType.CONFIDENTIAL);
        webClient.setAccessTokenValidity(3600); // 1 hour
        webClient.setRefreshTokenValidity(2592000); // 30 days
        return webClient;
    }
}