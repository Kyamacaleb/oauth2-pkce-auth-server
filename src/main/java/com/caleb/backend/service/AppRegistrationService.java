package com.caleb.backend.service;

import com.caleb.backend.dto.AppRegistrationRequest;
import com.caleb.backend.dto.AppRegistrationResponse;
import com.caleb.backend.model.OAuthClient;
import com.caleb.backend.repository.OAuthClientRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
public class AppRegistrationService {

    private static final String BASE_URL = "http://localhost:8080";
    private static final String AUTH_URL = BASE_URL + "/oauth2/authorize";
    private static final String TOKEN_URL = BASE_URL + "/oauth2/token";

    private final OAuthClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    public AppRegistrationService(OAuthClientRepository clientRepository,
                                  PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Register a new OAuth2 app. Always uses:
     *  - grant_type: authorization_code + refresh_token
     *  - code_challenge_method: S256 (PKCE)
     *  - token_type: Bearer
     *  - Client type: PUBLIC if no secret, CONFIDENTIAL if secret provided
     */
    public AppRegistrationResponse registerApp(AppRegistrationRequest request) {
        if (clientRepository.existsByClientId(request.getClientId())) {
            throw new IllegalArgumentException(
                    "An app with clientId '" + request.getClientId() + "' already exists.");
        }

        boolean isConfidential = StringUtils.hasText(request.getClientSecret());

        OAuthClient client = new OAuthClient();
        client.setClientId(request.getClientId());
        client.setClientName(request.getClientName());
        client.setClientSecret(isConfidential
                ? passwordEncoder.encode(request.getClientSecret())
                : null);
        client.setRedirectUris(new String[]{ request.getRedirectUrl() });
        client.setGrantTypes(new String[]{ "authorization_code", "refresh_token" });
        client.setScopes(new String[]{ "openid", "read:profile", "read:email" });
        client.setClientType(isConfidential
                ? OAuthClient.ClientType.CONFIDENTIAL
                : OAuthClient.ClientType.PUBLIC);
        client.setAccessTokenValidity(3600);       // 1 hour
        client.setRefreshTokenValidity(2592000);   // 30 days

        clientRepository.save(client);

        return buildResponse(client, isConfidential ? request.getClientSecret() : null);
    }

    public Optional<AppRegistrationResponse> findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(client -> buildResponse(client, null)); // never expose stored secret
    }

    private AppRegistrationResponse buildResponse(OAuthClient client, String rawSecret) {
        AppRegistrationResponse response = new AppRegistrationResponse();
        response.setClientId(client.getClientId());
        response.setClientName(client.getClientName());
        response.setRedirectUrl(client.getRedirectUriList().isEmpty()
                ? null : client.getRedirectUriList().get(0));
        response.setClientSecret(rawSecret);
        response.setAccessTokenType("Bearer");
        response.setGrantType("authorization_code");
        response.setCodeChallengeMethod("S256");
        response.setAuthorizationUrl(AUTH_URL);
        response.setAccessTokenUrl(TOKEN_URL);
        response.setClientType(client.getClientType().name());
        response.setMessage("App registered successfully. Use the authorizationUrl to begin the OAuth2 flow.");
        return response;
    }
}