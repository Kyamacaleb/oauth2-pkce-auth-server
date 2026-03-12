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

    // 1. Authorization Server filter chain  (/oauth2/* endpoints)
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.csrf(csrf -> csrf.disable());

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        // Redirect unauthenticated browser requests to the login page
        http.exceptionHandling(ex -> ex
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );

        // Allow the resource server to validate JWTs (used by /connect/userinfo)
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

    // 2. Default filter chain  (login, welcome, dashboard, callback)
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.ignoringRequestMatchers("/logout"))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/login", "/error",
                                "/webjars/**", "/css/**", "/js/**", "/images/**",
                                "/callback",
                                "/oauth2/jwks"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .usernameParameter("email")
                        .passwordParameter("password")
                        // After login, start the PKCE flow server-side
                        .defaultSuccessUrl("/start-auth", true)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .userDetailsService(userDetailsService);

        return http.build();
    }

    // JWT decoder (used by the Authorization Server for /connect/userinfo)
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // Authorization Server settings
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