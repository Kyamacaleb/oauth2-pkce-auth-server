package com.caleb.backend.service;

import com.caleb.backend.model.AuthorizationCode;
import com.caleb.backend.repository.AuthorizationCodeRepository;
import com.caleb.backend.repository.OAuthClientRepository;
import com.caleb.backend.repository.UserRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Primary
@Service
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(JpaOAuth2AuthorizationService.class);

    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final UserRepository userRepository;
    private final OAuthClientRepository oAuthClientRepository;

    // In-memory store for pending authorizations (before the code is issued, during consent).
    // Keyed by state parameter so findByToken() can look them up during consent POST.
    // Also used to carry PKCE attributes forward to the code-issued save() call.
    private final Map<String, OAuth2Authorization> pendingAuthorizations = new ConcurrentHashMap<>();

    public JpaOAuth2AuthorizationService(
            AuthorizationCodeRepository authorizationCodeRepository,
            RegisteredClientRepository registeredClientRepository,
            UserRepository userRepository,
            OAuthClientRepository oAuthClientRepository) {
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.registeredClientRepository = registeredClientRepository;
        this.userRepository = userRepository;
        this.oAuthClientRepository = oAuthClientRepository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");

        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken =
                authorization.getToken(OAuth2AuthorizationCode.class);

        if (codeToken == null) {
            // No code yet — pending authorization (consent stage).
            // Store keyed by state so consent POST can find it via findByToken().
            String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
            if (state != null) {
                pendingAuthorizations.put(state, authorization);
            }
            return;
        }

        // Code has been issued. Remove from pending store.
        String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        OAuth2Authorization pendingAuth = null;
        if (state != null) {
            pendingAuth = pendingAuthorizations.remove(state);
        }

        String codeValue = codeToken.getToken().getTokenValue();

        AuthorizationCode authCode = authorizationCodeRepository
                .findByCode(codeValue)
                .orElse(new AuthorizationCode());

        authCode.setCode(codeValue);
        authCode.setExpiresAt(
                codeToken.getToken().getExpiresAt()
                        .atZone(ZoneOffset.UTC)
                        .toLocalDateTime()
        );
        // Persist issuedAt so toOAuth2Authorization() can reconstruct the token correctly
        if (codeToken.getToken().getIssuedAt() != null) {
            authCode.setCreatedAt(
                    codeToken.getToken().getIssuedAt()
                            .atZone(ZoneOffset.UTC)
                            .toLocalDateTime()
            );
        }

        // --- PKCE extraction strategy (4 sources, in priority order) ---

        // 1. Token metadata
        Map<String, Object> metadata = codeToken.getMetadata();
        log.debug("[PKCE] token metadata keys: {}", metadata != null ? metadata.keySet() : "null");
        if (metadata != null) {
            Object cc = metadata.get("code_challenge");
            Object ccm = metadata.get("code_challenge_method");
            if (cc != null) authCode.setCodeChallenge(cc.toString());
            if (ccm != null) authCode.setCodeChallengeMethod(ccm.toString());
        }

        // 2. Top-level authorization attributes (raw string keys)
        if (authCode.getCodeChallenge() == null) {
            Object cc = authorization.getAttribute("code_challenge");
            if (cc != null) authCode.setCodeChallenge(cc.toString());
        }
        if (authCode.getCodeChallengeMethod() == null) {
            Object ccm = authorization.getAttribute("code_challenge_method");
            if (ccm != null) authCode.setCodeChallengeMethod(ccm.toString());
        }

        // 3. OAuth2AuthorizationRequest — THIS is where Spring AS actually stores PKCE.
        //    When consent is already granted, Spring skips the pending-auth stage and goes
        //    straight to issuing the code. The PKCE challenge lives inside the
        //    OAuth2AuthorizationRequest object stored as an authorization attribute.
        if (authCode.getCodeChallenge() == null) {
            OAuth2AuthorizationRequest authRequest =
                    authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
            if (authRequest != null) {
                Map<String, Object> additionalParams = authRequest.getAdditionalParameters();
                log.debug("[PKCE] OAuth2AuthorizationRequest additionalParameters: {}", additionalParams);
                if (additionalParams != null) {
                    Object cc = additionalParams.get("code_challenge");
                    Object ccm = additionalParams.get("code_challenge_method");
                    log.debug("[PKCE] from OAuth2AuthorizationRequest — code_challenge={}, method={}", cc, ccm);
                    if (cc != null) authCode.setCodeChallenge(cc.toString());
                    if (ccm != null) authCode.setCodeChallengeMethod(ccm.toString());
                }
            } else {
                log.debug("[PKCE] OAuth2AuthorizationRequest attribute is null");
            }
        }

        // 4. Pending authorization (only relevant when consent flow was shown)
        if (pendingAuth != null && authCode.getCodeChallenge() == null) {
            OAuth2AuthorizationRequest pendingAuthRequest =
                    pendingAuth.getAttribute(OAuth2AuthorizationRequest.class.getName());
            if (pendingAuthRequest != null) {
                Map<String, Object> additionalParams = pendingAuthRequest.getAdditionalParameters();
                if (additionalParams != null) {
                    Object cc = additionalParams.get("code_challenge");
                    Object ccm = additionalParams.get("code_challenge_method");
                    if (cc != null) authCode.setCodeChallenge(cc.toString());
                    if (ccm != null) authCode.setCodeChallengeMethod(ccm.toString());
                }
            }
        }

        log.debug("[PKCE] final — code_challenge={}, method={}", authCode.getCodeChallenge(), authCode.getCodeChallengeMethod());

        // Redirect URI
        authCode.setRedirectUri(authorization.getAttribute(OAuth2ParameterNames.REDIRECT_URI));

        // Associate user
        String principalName = authorization.getPrincipalName();
        userRepository.findByUsername(principalName).ifPresent(authCode::setUser);

        // Associate client
        String registeredClientId = authorization.getRegisteredClientId();
        try {
            long id = Long.parseLong(registeredClientId);
            oAuthClientRepository.findById(id).ifPresent(authCode::setClient);
        } catch (NumberFormatException e) {
            oAuthClientRepository.findByClientId(registeredClientId).ifPresent(authCode::setClient);
        }

        // Scopes
        if (authorization.getAuthorizedScopes() != null && !authorization.getAuthorizedScopes().isEmpty()) {
            authCode.setScopes(authorization.getAuthorizedScopes().toArray(new String[0]));
        }

        authorizationCodeRepository.save(authCode);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");

        String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        if (state != null) {
            pendingAuthorizations.remove(state);
        }

        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken =
                authorization.getToken(OAuth2AuthorizationCode.class);
        if (codeToken != null) {
            authorizationCodeRepository
                    .findByCode(codeToken.getToken().getTokenValue())
                    .ifPresent(authorizationCodeRepository::delete);
        }
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        try {
            return authorizationCodeRepository
                    .findById(Long.parseLong(id))
                    .map(this::toOAuth2Authorization)
                    .orElse(null);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");

        // Check pending store first (state-based lookup during consent POST)
        OAuth2Authorization pending = pendingAuthorizations.get(token);
        if (pending != null) {
            return pending;
        }

        if (tokenType == null || OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return authorizationCodeRepository
                    .findByCode(token)
                    .map(this::toOAuth2Authorization)
                    .orElse(null);
        }

        return null;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private OAuth2Authorization toOAuth2Authorization(AuthorizationCode authCode) {
        if (authCode == null || authCode.getClient() == null || authCode.getUser() == null) {
            return null;
        }

        RegisteredClient registeredClient = registeredClientRepository
                .findByClientId(authCode.getClient().getClientId());
        if (registeredClient == null) {
            return null;
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .id(String.valueOf(authCode.getId()))
                .principalName(authCode.getUser().getUsername())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(new HashSet<>(authCode.getScopeList()));

        // redirect_uri must not be null
        if (authCode.getRedirectUri() != null) {
            builder.attribute(OAuth2ParameterNames.REDIRECT_URI, authCode.getRedirectUri());
        }

        // Restore PKCE attributes at the authorization level
        // CodeVerifierAuthenticator reads these via authorization.getAttribute("code_challenge")
        if (authCode.getCodeChallenge() != null) {
            builder.attribute("code_challenge", authCode.getCodeChallenge());
        }
        if (authCode.getCodeChallengeMethod() != null) {
            builder.attribute("code_challenge_method", authCode.getCodeChallengeMethod());
        }

        // Rebuild the code token
        if (authCode.getCode() != null && authCode.getExpiresAt() != null) {
            java.time.Instant expiresAt = authCode.getExpiresAt().toInstant(ZoneOffset.UTC);

            // issuedAt: use createdAt if present and valid, otherwise derive from expiresAt
            java.time.Instant issuedAt;
            if (authCode.getCreatedAt() != null) {
                java.time.Instant candidate = authCode.getCreatedAt().toInstant(ZoneOffset.UTC);
                // Guard against epoch/zero stored in DB
                issuedAt = candidate.isBefore(expiresAt) ? candidate : expiresAt.minusSeconds(300);
            } else {
                issuedAt = expiresAt.minusSeconds(300);
            }

            OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(
                    authCode.getCode(),
                    issuedAt,
                    expiresAt
            );

            Map<String, Object> tokenMetadata = new HashMap<>();
            tokenMetadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
            if (authCode.getCodeChallenge() != null) {
                tokenMetadata.put("code_challenge", authCode.getCodeChallenge());
            }
            if (authCode.getCodeChallengeMethod() != null) {
                tokenMetadata.put("code_challenge_method", authCode.getCodeChallengeMethod());
            }

            builder.token(code, t -> t.putAll(tokenMetadata));
        }

        return builder.build();
    }
}