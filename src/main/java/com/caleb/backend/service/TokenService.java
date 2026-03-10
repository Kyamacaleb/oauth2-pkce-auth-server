package com.caleb.backend.service;

import com.caleb.backend.model.*;
import com.caleb.backend.repository.AccessTokenRepository;
import com.caleb.backend.repository.RefreshTokenRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

@Service
public class TokenService {

    private final AccessTokenRepository accessTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtEncoder jwtEncoder;
    private final PKCEService pkceService;

    public TokenService(
            AccessTokenRepository accessTokenRepository,
            RefreshTokenRepository refreshTokenRepository,
            JwtEncoder jwtEncoder,
            PKCEService pkceService) {
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtEncoder = jwtEncoder;
        this.pkceService = pkceService;
    }

    /**
     * Generate the access token (JWT) using Spring's JwtEncoder
     */
    @Transactional
    public AccessToken generateAccessToken(User user, OAuthClient client, List<String> scopes) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(client.getAccessTokenValidity());

        String tokenId = UUID.randomUUID().toString();

        // Build JWT claims
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:8080")
                .subject(user.getUsername())
                .id(tokenId)
                .issuedAt(now)
                .expiresAt(expiresAt)
                .claim("client_id", client.getClientId())
                .claim("scope", String.join(" ", scopes))
                .claim("user_id", user.getId())
                .claim("token_type", "access_token")
                .build();

        // Encode JWT
        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));
        String tokenValue = jwt.getTokenValue();

        // Create and save the access token
        AccessToken accessToken = new AccessToken();
        accessToken.setTokenId(tokenId);
        accessToken.setTokenValue(tokenValue);
        accessToken.setUser(user);
        accessToken.setClient(client);
        accessToken.setScopes(scopes.toArray(new String[0]));
        accessToken.setExpiresAt(LocalDateTime.ofInstant(expiresAt, ZoneOffset.UTC));
        accessToken.setRevoked(false);

        return accessTokenRepository.save(accessToken);
    }

    /**
     * Generate refresh token
     */
    @Transactional
    public RefreshToken generateRefreshToken(User user, OAuthClient client, AccessToken accessToken) {
        String tokenId = UUID.randomUUID().toString();
        String tokenValue = UUID.randomUUID().toString(); // Simple opaque token

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setTokenId(tokenId);
        refreshToken.setTokenValue(tokenValue);
        refreshToken.setUser(user);
        refreshToken.setClient(client);
        refreshToken.setAccessToken(accessToken);
        refreshToken.setExpiresAt(LocalDateTime.now().plusSeconds(client.getRefreshTokenValidity()));
        refreshToken.setRevoked(false);

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Validate access token
     */
    public boolean validateAccessToken(String tokenValue) {
        try {
            AccessToken accessToken = accessTokenRepository.findByTokenValue(tokenValue)
                    .orElse(null);

            return accessToken != null && !accessToken.isExpired();

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get user from access token
     */
    public User getUserFromAccessToken(String tokenValue) {
        AccessToken accessToken = accessTokenRepository.findByTokenValue(tokenValue)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (accessToken.isExpired()) {
            throw new RuntimeException("Token expired");
        }

        return accessToken.getUser();
    }

    /**
     * Refresh access token using refresh token
     */
    @Transactional
    public AccessToken refreshAccessToken(String refreshTokenValue) {
        RefreshToken refreshToken = refreshTokenRepository.findByTokenValue(refreshTokenValue)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (refreshToken.isExpired()) {
            throw new RuntimeException("Refresh token expired");
        }

        // Get the scopes from the associated access token
        List<String> scopes = refreshToken.getAccessToken() != null ?
                refreshToken.getAccessToken().getScopeList() : List.of();

        // Revoke old tokens
        refreshToken.setRevoked(true);
        if (refreshToken.getAccessToken() != null) {
            refreshToken.getAccessToken().setRevoked(true);
            accessTokenRepository.save(refreshToken.getAccessToken());
        }
        refreshTokenRepository.save(refreshToken);

        // Generate new tokens
        AccessToken newAccessToken = generateAccessToken(
                refreshToken.getUser(),
                refreshToken.getClient(),
                scopes
        );

        generateRefreshToken(refreshToken.getUser(), refreshToken.getClient(), newAccessToken);

        return newAccessToken;
    }

    /**
     * Revoke all user tokens for a client
     */
    @Transactional
    public void revokeUserTokens(User user, OAuthClient client) {
        accessTokenRepository.revokeUserTokensForClient(user, client);
        refreshTokenRepository.revokeUserTokensForClient(user, client);
    }
}