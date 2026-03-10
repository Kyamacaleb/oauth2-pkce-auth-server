package com.caleb.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

@Entity
@Table(name = "authorization_codes")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String code;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuthClient client;

    @Column(name = "redirect_uri", length = 500)
    private String redirectUri;

    @Column(name = "scopes", columnDefinition = "TEXT[]")
    private String[] scopes;

    @Column(name = "code_challenge")
    private String codeChallenge;

    @Column(name = "code_challenge_method", length = 10)
    private String codeChallengeMethod;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        if (expiresAt == null) {
            expiresAt = LocalDateTime.now().plusMinutes(10); // Auth codes valid for 10 minutes
        }
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    public List<String> getScopeList() {
        return scopes != null ? Arrays.asList(scopes) : List.of();
    }

    // Helper method to validate PKCE challenge
    public boolean validatePkce(String codeVerifier) {
        if (codeChallengeMethod == null || codeChallenge == null) {
            return true; // No PKCE required
        }

        if ("S256".equals(codeChallengeMethod)) {
            // We'll implement the actual verification in the service
            return true; // Placeholder - actual verification happens in service
        } else if ("plain".equals(codeChallengeMethod)) {
            return codeChallenge.equals(codeVerifier);
        }

        return false;
    }
}