package com.caleb.backend.service;

import com.caleb.backend.model.OAuthClient;
import com.caleb.backend.model.UserConsent;
import com.caleb.backend.repository.OAuthClientRepository;
import com.caleb.backend.repository.UserConsentRepository;
import com.caleb.backend.repository.UserRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.time.LocalDateTime;

@Primary
@Service
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final UserConsentRepository consentRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final UserRepository userRepository;
    private final OAuthClientRepository clientRepository;

    public JpaOAuth2AuthorizationConsentService(
            UserConsentRepository consentRepository,
            RegisteredClientRepository registeredClientRepository,
            UserRepository userRepository,
            OAuthClientRepository clientRepository) {
        this.consentRepository = consentRepository;
        this.registeredClientRepository = registeredClientRepository;
        this.userRepository = userRepository;
        this.clientRepository = clientRepository;
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");

        var user = userRepository.findByEmail(authorizationConsent.getPrincipalName())
                .orElseThrow(() -> new DataRetrievalFailureException(
                        "User not found: " + authorizationConsent.getPrincipalName()));

        // registeredClientId is the numeric DB id (e.g. "1"), resolve via findById
        OAuthClient client = resolveClient(authorizationConsent.getRegisteredClientId());

        UserConsent consent = consentRepository
                .findByUserAndClient(user, client)
                .orElse(new UserConsent());

        if (consent.getUser() == null) consent.setUser(user);
        if (consent.getClient() == null) consent.setClient(client);

        consent.setScopes(authorizationConsent.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(scope -> scope.startsWith("SCOPE_"))
                .map(scope -> scope.substring(6))
                .toArray(String[]::new));

        consent.setExpiresAt(LocalDateTime.now().plusYears(1));
        consentRepository.save(consent);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");

        var user = userRepository.findByEmail(authorizationConsent.getPrincipalName())
                .orElseThrow(() -> new DataRetrievalFailureException("User not found"));

        OAuthClient client = resolveClient(authorizationConsent.getRegisteredClientId());

        consentRepository.findByUserAndClient(user, client)
                .ifPresent(consentRepository::delete);
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");

        var user = userRepository.findByEmail(principalName).orElse(null);
        if (user == null) return null;

        OAuthClient client = resolveClientOrNull(registeredClientId);
        if (client == null) return null;

        return consentRepository.findByUserAndClient(user, client)
                .map(consent -> toOAuth2AuthorizationConsent(consent, registeredClientId, principalName))
                .orElse(null);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Spring Authorization Server passes the RegisteredClient.getId() value as
     * registeredClientId — which in our case is the numeric DB primary key (e.g. "1").
     * Try numeric lookup first, fall back to clientId string lookup.
     */
    private OAuthClient resolveClient(String registeredClientId) {
        OAuthClient client = resolveClientOrNull(registeredClientId);
        if (client == null) {
            throw new DataRetrievalFailureException("Client not found: " + registeredClientId);
        }
        return client;
    }

    private OAuthClient resolveClientOrNull(String registeredClientId) {
        // Try numeric ID first (Spring AS passes RegisteredClient.getId())
        try {
            long id = Long.parseLong(registeredClientId);
            return clientRepository.findById(id).orElse(null);
        } catch (NumberFormatException e) {
            // Fall back to clientId string lookup
            return clientRepository.findByClientId(registeredClientId).orElse(null);
        }
    }

    private OAuth2AuthorizationConsent toOAuth2AuthorizationConsent(
            UserConsent consent, String registeredClientId, String principalName) {

        RegisteredClient registeredClient = registeredClientRepository.findById(registeredClientId);
        if (registeredClient == null) {
            // Also try by clientId string
            registeredClient = registeredClientRepository.findByClientId(
                    consent.getClient().getClientId());
        }
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "Registered client not found: " + registeredClientId);
        }

        OAuth2AuthorizationConsent.Builder builder =
                OAuth2AuthorizationConsent.withId(registeredClientId, principalName);

        if (consent.getScopes() != null) {
            for (String scope : consent.getScopes()) {
                builder.scope(scope);
                builder.authority(() -> "SCOPE_" + scope);
            }
        }

        return builder.build();
    }
}