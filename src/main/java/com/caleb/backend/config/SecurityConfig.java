package com.caleb.backend.config;

import com.caleb.backend.security.UserDetailsServiceImpl;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsServiceImpl userDetailsService;

    public SecurityConfig(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    // -------------------------------------------------------------------------
    // 1. Authorization Server filter chain (handles /oauth2/* endpoints)
    // -------------------------------------------------------------------------
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.csrf(csrf -> csrf.disable());

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(ep -> ep
                        .consentPage("/oauth2/consent")
                        .errorResponseHandler((request, response, exception) -> {
                            if (exception instanceof OAuth2AuthorizationCodeRequestAuthenticationException ex) {
                                System.err.println("OAuth2 auth error: " + ex.getError().getErrorCode()
                                        + " — " + ex.getError().getDescription());
                            }
                            response.sendError(400, exception.getMessage());
                        })
                )
                .oidc(Customizer.withDefaults());

        http.exceptionHandling(ex -> ex
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    // -------------------------------------------------------------------------
    // 2. Default filter chain (login page, dashboard, app registration API)
    // -------------------------------------------------------------------------
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.ignoringRequestMatchers(
                        "/api/**",
                        "/oauth2/consent"
                ))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/login", "/error", "/webjars/**",
                                "/css/**", "/js/**", "/images/**",
                                "/api/v1/apps",
                                "/api/v1/apps/**",
                                "/oauth2/jwks",
                                "/oauth2/consent",
                                "/oauth2/consent/state"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .usernameParameter("email")
                        .passwordParameter("password")
                        .defaultSuccessUrl("/dashboard", false)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .userDetailsService(userDetailsService);
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8080")
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .jwkSetEndpoint("/oauth2/jwks")
                .oidcUserInfoEndpoint("/connect/userinfo")
                .build();
    }
}