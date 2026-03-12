package com.caleb.backend.config;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * Jackson Mixin that registers com.caleb.backend.model.User on Spring
 * Security's Jackson allowlist.
 *
 * Spring AS serializes the full OAuth2Authorization (including the
 * authenticated principal) to JSON when storing it in Postgres. On read-back,
 * Jackson's security module rejects unknown classes. This Mixin tells it
 * that User is safe to deserialize.
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