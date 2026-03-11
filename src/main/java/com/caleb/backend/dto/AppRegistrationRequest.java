package com.caleb.backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AppRegistrationRequest {
    @NotBlank(message = "clientId is required")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "clientId must be alphanumeric (hyphens and underscores allowed)")
    private String clientId;

    @NotBlank(message = "clientName is required")
    private String clientName;

    @NotBlank(message = "redirectUrl is required")
    @Pattern(regexp = "^https?://.*", message = "redirectUrl must be a valid HTTP/HTTPS URL")
    private String redirectUrl;
    private String clientSecret;

}