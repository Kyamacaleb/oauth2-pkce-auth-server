package com.caleb.backend.config;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * Spring Authorization Server serializes the entire OAuth2Authorization
 * (including the principal) to JSON when storing it in the DB. When it
 * reads it back, Spring Security's Jackson allowlist blocks unknown classes.
 * Registering this Mixin tells Jackson: "User is safe to deserialize".
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(
        fieldVisibility    = JsonAutoDetect.Visibility.ANY,
        getterVisibility   = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE
)
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonDeserialize
public abstract class UserMixin {
}