package com.caleb.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name = "oauth_clients")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuthClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", unique = true, nullable = false, length = 100)
    private String clientId;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "client_name", nullable = false, length = 200)
    private String clientName;

    @Column(name = "redirect_uris", columnDefinition = "TEXT[]")
    private String[] redirectUris;

    @Column(name = "grant_types", columnDefinition = "TEXT[]")
    private String[] grantTypes;

    @Column(name = "scopes", columnDefinition = "TEXT[]")
    private String[] scopes;

    @Column(name = "client_type", nullable = false, length = 20)
    @Enumerated(EnumType.STRING)
    private ClientType clientType;

    @Column(name = "access_token_validity")
    private Integer accessTokenValidity = 3600;

    @Column(name = "refresh_token_validity")
    private Integer refreshTokenValidity = 2592000;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public enum ClientType {
        PUBLIC, CONFIDENTIAL
    }

    // Helper methods to convert array fields to lists
    public List<String> getRedirectUriList() {
        return redirectUris != null ? Arrays.asList(redirectUris) : List.of();
    }

    public List<String> getGrantTypeList() {
        return grantTypes != null ? Arrays.asList(grantTypes) : List.of();
    }

    public List<String> getScopeList() {
        return scopes != null ? Arrays.asList(scopes) : List.of();
    }

    // Check if client supports PKCE (public clients require PKCE)
    public boolean requiresPkce() {
        return clientType == ClientType.PUBLIC;
    }
}