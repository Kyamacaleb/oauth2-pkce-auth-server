package com.caleb.backend.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AppRegistrationResponse {

    private String clientId;
    private String clientName;
    private String clientSecret;
    private String redirectUrl;
    private String accessTokenType;
    private String grantType;
    private String codeChallengeMethod;
    private String authorizationUrl;
    private String accessTokenUrl;
    private String clientType;
    private String message;

}