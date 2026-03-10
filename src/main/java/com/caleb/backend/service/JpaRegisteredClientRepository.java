package com.caleb.backend.service;

import com.caleb.backend.model.OAuthClient;
import com.caleb.backend.repository.OAuthClientRepository;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Primary
@Service
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final OAuthClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JpaRegisteredClientRepository(
            OAuthClientRepository clientRepository,
            PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;

        ClassLoader classLoader = JpaRegisteredClientRepository.class.getClassLoader();
        List<Module> securityModules = new ArrayList<>();
        securityModules.add(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.registerModules(securityModules);
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        OAuthClient client = new OAuthClient();
        client.setClientId(registeredClient.getClientId());
        client.setClientSecret(registeredClient.getClientSecret());
        client.setClientName(registeredClient.getClientName());

        client.setRedirectUris(registeredClient.getRedirectUris().toArray(new String[0]));

        client.setGrantTypes(registeredClient.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .toArray(String[]::new));

        client.setScopes(registeredClient.getScopes().toArray(new String[0]));

        boolean hasSecret = StringUtils.hasText(registeredClient.getClientSecret());
        client.setClientType(hasSecret ? OAuthClient.ClientType.CONFIDENTIAL : OAuthClient.ClientType.PUBLIC);

        TokenSettings tokenSettings = registeredClient.getTokenSettings();
        if (tokenSettings != null) {
            client.setAccessTokenValidity((int) tokenSettings.getAccessTokenTimeToLive().getSeconds());
            client.setRefreshTokenValidity((int) tokenSettings.getRefreshTokenTimeToLive().getSeconds());
        }

        clientRepository.save(client);
    }

    @Override
    public RegisteredClient findById(String id) {
        return clientRepository.findById(Long.parseLong(id))
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    private RegisteredClient toRegisteredClient(OAuthClient client) {
        Set<String> clientAuthenticationMethods = client.getClientType() == OAuthClient.ClientType.PUBLIC
                ? Set.of(ClientAuthenticationMethod.NONE.getValue())
                : Set.of(
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(),
                ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());

        Set<String> authorizationGrantTypes = new HashSet<>(client.getGrantTypeList());
        Set<String> scopes = new HashSet<>(client.getScopeList());

        RegisteredClient.Builder builder = RegisteredClient.withId(String.valueOf(client.getId()))
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientName(client.getClientName())
                .clientIdIssuedAt(client.getCreatedAt().toInstant(ZoneOffset.UTC))
                .clientAuthenticationMethods(methods ->
                        clientAuthenticationMethods.forEach(m ->
                                methods.add(new ClientAuthenticationMethod(m))))
                .authorizationGrantTypes(grants ->
                        authorizationGrantTypes.forEach(g ->
                                grants.add(new AuthorizationGrantType(g))))
                .redirectUris(uris -> uris.addAll(client.getRedirectUriList()))
                .scopes(s -> s.addAll(scopes));

        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();
        tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofSeconds(client.getAccessTokenValidity()));
        tokenSettingsBuilder.refreshTokenTimeToLive(Duration.ofSeconds(client.getRefreshTokenValidity()));
        tokenSettingsBuilder.reuseRefreshTokens(false);
        builder.tokenSettings(tokenSettingsBuilder.build());

        ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder();
        clientSettingsBuilder.requireAuthorizationConsent(true);
        clientSettingsBuilder.requireProofKey(client.getClientType() == OAuthClient.ClientType.PUBLIC);
        builder.clientSettings(clientSettingsBuilder.build());

        return builder.build();
    }
}