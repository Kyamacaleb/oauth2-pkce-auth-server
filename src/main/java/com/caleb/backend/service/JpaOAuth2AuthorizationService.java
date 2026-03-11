package com.caleb.backend.service;

import com.caleb.backend.model.AccessToken;
import com.caleb.backend.model.AuthorizationCode;
import com.caleb.backend.model.OAuthClient;
import com.caleb.backend.model.User;
import com.caleb.backend.repository.AccessTokenRepository;
import com.caleb.backend.repository.AuthorizationCodeRepository;
import com.caleb.backend.repository.OAuthClientRepository;
import com.caleb.backend.repository.UserRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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

import java.security.Principal;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Primary
@Service
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(JpaOAuth2AuthorizationService.class);

    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final UserRepository userRepository;
    private final OAuthClientRepository oAuthClientRepository;
    private final AccessTokenRepository accessTokenRepository;

    private final Map<String, OAuth2Authorization> pendingAuthorizations = new ConcurrentHashMap<>();

    public JpaOAuth2AuthorizationService(
            AuthorizationCodeRepository authorizationCodeRepository,
            RegisteredClientRepository registeredClientRepository,
            UserRepository userRepository,
            OAuthClientRepository oAuthClientRepository,
            AccessTokenRepository accessTokenRepository) {
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.registeredClientRepository = registeredClientRepository;
        this.userRepository = userRepository;
        this.oAuthClientRepository = oAuthClientRepository;
        this.accessTokenRepository = accessTokenRepository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");

        log.debug("[save] principalName={}, registeredClientId={}",
                authorization.getPrincipalName(), authorization.getRegisteredClientId());

        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken =
                authorization.getToken(OAuth2AuthorizationCode.class);

        if (codeToken == null) {
            // Pending authorization (consent stage) — store by state
            String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
            if (state != null) {
                pendingAuthorizations.put(state, authorization);
                log.debug("[save] stored pending authorization for state={}", state);
            }
            return;
        }

        // Code has been issued — remove from pending store
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

        if (codeToken.getToken().getIssuedAt() != null) {
            authCode.setCreatedAt(
                    codeToken.getToken().getIssuedAt()
                            .atZone(ZoneOffset.UTC)
                            .toLocalDateTime()
            );
        }

        // PKCE extraction — 4 sources in priority order

        // 1. Token metadata
        Map<String, Object> metadata = codeToken.getMetadata();
        log.debug("[PKCE] token metadata keys: {}", metadata != null ? metadata.keySet() : "null");
        if (metadata != null) {
            Object cc = metadata.get("code_challenge");
            Object ccm = metadata.get("code_challenge_method");
            if (cc != null) authCode.setCodeChallenge(cc.toString());
            if (ccm != null) authCode.setCodeChallengeMethod(ccm.toString());
        }

        // 2. Top-level authorization attributes
        if (authCode.getCodeChallenge() == null) {
            Object cc = authorization.getAttribute("code_challenge");
            if (cc != null) authCode.setCodeChallenge(cc.toString());
        }
        if (authCode.getCodeChallengeMethod() == null) {
            Object ccm = authorization.getAttribute("code_challenge_method");
            if (ccm != null) authCode.setCodeChallengeMethod(ccm.toString());
        }

        // 3. OAuth2AuthorizationRequest additionalParameters
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

        // 4. Pending authorization (consent flow)
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
        userRepository.findByEmail(principalName).ifPresent(authCode::setUser);

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

        // -----------------------------------------------------------------------
        // Spring AS invalidates the code and issues the access token in ONE save().
        // -----------------------------------------------------------------------
        OAuth2Authorization.Token<org.springframework.security.oauth2.core.OAuth2AccessToken> accessTokenToken =
                authorization.getToken(org.springframework.security.oauth2.core.OAuth2AccessToken.class);

        if (accessTokenToken != null) {
            String tokenValue = accessTokenToken.getToken().getTokenValue();
            if (accessTokenRepository.findByTokenValue(tokenValue).isEmpty()) {
                OAuthClient client = authCode.getClient();
                User user = authCode.getUser();

                if (client != null && user != null) {
                    AccessToken at = new AccessToken();
                    at.setTokenId(UUID.randomUUID().toString());
                    at.setTokenValue(tokenValue);
                    at.setUser(user);
                    at.setClient(client);
                    at.setScopes(authorization.getAuthorizedScopes().toArray(new String[0]));
                    at.setExpiresAt(accessTokenToken.getToken().getExpiresAt()
                            .atZone(ZoneOffset.UTC).toLocalDateTime());
                    at.setRevoked(false);
                    accessTokenRepository.save(at);
                    log.info("[save] ✅ persisted access token for user={} client={}", principalName, client.getClientId());
                } else {
                    log.warn("[save] ⚠️ could not persist access token — client={} user={}", client, user);
                }
            } else {
                log.debug("[save] access token already exists, skipping");
            }
        }
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

        log.debug("[findByToken] token={}, type={}", token, tokenType);

        // Check pending store first
        OAuth2Authorization pending = pendingAuthorizations.get(token);
        if (pending != null) {
            log.debug("[findByToken] found in pending store");
            return pending;
        }

        // Authorization code lookup
        if (tokenType == null || OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            Optional<AuthorizationCode> codeOpt = authorizationCodeRepository.findByCode(token);
            if (codeOpt.isPresent()) {
                log.debug("[findByToken] found authorization code in DB");
                return toOAuth2Authorization(codeOpt.get());
            }
        }

        // Access token lookup — needed by OidcUserInfoAuthenticationProvider
        if (tokenType == null || OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            Optional<com.caleb.backend.model.AccessToken> accessTokenOpt =
                    accessTokenRepository.findByTokenValue(token);
            if (accessTokenOpt.isPresent()) {
                log.debug("[findByToken] found access token in DB");
                return toOAuth2AuthorizationFromAccessToken(accessTokenOpt.get());
            } else {
                log.debug("[findByToken] access token NOT found in DB");
            }
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

        String redirectUri = authCode.getRedirectUri();
        if (redirectUri == null && !authCode.getClient().getRedirectUriList().isEmpty()) {
            redirectUri = authCode.getClient().getRedirectUriList().get(0);
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .id(String.valueOf(authCode.getId()))
                .principalName(authCode.getUser().getUsername())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(new HashSet<>(authCode.getScopeList()));

        if (redirectUri != null) {
            builder.attribute(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
        }

        if (authCode.getCodeChallenge() != null) {
            builder.attribute("code_challenge", authCode.getCodeChallenge());
        }
        if (authCode.getCodeChallengeMethod() != null) {
            builder.attribute("code_challenge_method", authCode.getCodeChallengeMethod());
        }

        // Reconstruct OAuth2AuthorizationRequest with PKCE params
        Map<String, Object> additionalParams = new HashMap<>();
        if (authCode.getCodeChallenge() != null) {
            additionalParams.put("code_challenge", authCode.getCodeChallenge());
            additionalParams.put("code_challenge_method",
                    authCode.getCodeChallengeMethod() != null ? authCode.getCodeChallengeMethod() : "S256");
        }

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest
                .authorizationCode()
                .clientId(authCode.getClient().getClientId())
                .authorizationUri("http://localhost:8080/oauth2/authorize")
                .redirectUri(redirectUri)
                .scopes(new HashSet<>(authCode.getScopeList()))
                .state("restored")
                .additionalParameters(additionalParams)
                .build();

        builder.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);

        // Rebuild the code token
        if (authCode.getCode() != null && authCode.getExpiresAt() != null) {
            java.time.Instant expiresAt = authCode.getExpiresAt().toInstant(ZoneOffset.UTC);

            java.time.Instant issuedAt;
            if (authCode.getCreatedAt() != null) {
                java.time.Instant candidate = authCode.getCreatedAt().toInstant(ZoneOffset.UTC);
                issuedAt = candidate.isBefore(expiresAt) ? candidate : expiresAt.minusSeconds(300);
            } else {
                issuedAt = expiresAt.minusSeconds(300);
            }

            OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(
                    authCode.getCode(), issuedAt, expiresAt);

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

        // Principal authentication
        userRepository.findByEmail(authCode.getUser().getEmail()).ifPresent(user -> {
            UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(
                    user, null, user.getAuthorities());
            builder.attribute(Principal.class.getName(), principal);
        });

        return builder.build();
    }

    private OAuth2Authorization toOAuth2AuthorizationFromAccessToken(
            AccessToken accessToken) {

        if (accessToken == null) {
            return null;
        }

        // Eagerly load client and user to avoid LazyInitializationException
        if (accessToken.getClient() == null || accessToken.getUser() == null) {
            return null;
        }

        // Force load via repository to avoid lazy proxy issues
        OAuthClient client = oAuthClientRepository
                .findById(accessToken.getClient().getId())
                .orElse(null);
        if (client == null) return null;

        User user = userRepository
                .findById(accessToken.getUser().getId())
                .orElse(null);
        if (user == null) return null;

        RegisteredClient registeredClient = registeredClientRepository
                .findByClientId(client.getClientId());
        if (registeredClient == null) return null;

        UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());

        java.time.Instant issuedAt = accessToken.getCreatedAt().toInstant(ZoneOffset.UTC);
        java.time.Instant expiresAt = accessToken.getExpiresAt().toInstant(ZoneOffset.UTC);

        org.springframework.security.oauth2.core.OAuth2AccessToken oAuth2AccessToken =
                new org.springframework.security.oauth2.core.OAuth2AccessToken(
                        org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER,
                        accessToken.getTokenValue(),
                        issuedAt,
                        expiresAt,
                        new HashSet<>(accessToken.getScopeList())
                );

        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(String.valueOf(accessToken.getId()))
                .principalName(user.getUsername())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(new HashSet<>(accessToken.getScopeList()))
                .attribute(Principal.class.getName(), principal)
                .token(oAuth2AccessToken, metadata ->
                        metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                accessToken.getRevoked()))
                .build();
    }
}