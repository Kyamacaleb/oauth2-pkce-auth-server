package com.caleb.backend.controller;

import com.caleb.backend.util.PKCEUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Handles the complete OAuth2 + PKCE flow server-side.
 *
 * Routes:
 *   GET /             → welcome page
 *   GET /login        → login page (rendered, Spring Security handles POST)
 *   GET /start-auth   → generate PKCE, redirect to /oauth2/authorize
 *   GET /callback     → receive auth code, exchange for token, store in session
 *   GET /refresh      → use refresh token to silently get a new access token
 *   GET /dashboard    → display token + metadata
 *
 * Base URL is read from app.base-url so this works in any environment
 * without code changes.
 */
@Controller
public class AuthFlowController {

    private static final Logger log = LoggerFactory.getLogger(AuthFlowController.class);

    private static final String CLIENT_ID        = "frontend-app";
    private static final String SCOPES           = "openid read:profile read:email";

    // Session keys
    private static final String SESSION_VERIFIER     = "pkce_code_verifier";
    private static final String SESSION_STATE        = "oauth2_state";
    private static final String SESSION_TOKEN        = "access_token";
    private static final String SESSION_REFRESH      = "refresh_token";
    private static final String SESSION_TOKEN_META   = "access_token_meta";

    private static final DateTimeFormatter EXPIRY_FMT =
            DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm:ss")
                    .withZone(ZoneId.of("UTC"));

    @Value("${app.base-url:http://localhost:8080}")
    private String appBaseUrl;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient   httpClient   = HttpClient.newHttpClient();

    // ── Derived redirect URI (lazily computed once) ──────────────────────────
    private String redirectUri() {
        return appBaseUrl + "/callback";
    }

    private String tokenEndpoint() {
        return appBaseUrl + "/oauth2/token";
    }

    private String authorizeEndpoint() {
        return appBaseUrl + "/oauth2/authorize";
    }

    // -------------------------------------------------------------------------
    // Welcome
    // -------------------------------------------------------------------------
    @GetMapping("/")
    public String welcomePage() {
        return "welcome";
    }

    // -------------------------------------------------------------------------
    // Login page (Spring Security handles the POST automatically)
    // -------------------------------------------------------------------------
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    // -------------------------------------------------------------------------
    // Start auth: generate PKCE params, store in session, redirect to AS
    // -------------------------------------------------------------------------
    @GetMapping("/start-auth")
    public String startAuth(HttpSession session) {
        String codeVerifier  = PKCEUtil.generateCodeVerifier();
        String codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier);
        String state         = UUID.randomUUID().toString();

        session.setAttribute(SESSION_VERIFIER, codeVerifier);
        session.setAttribute(SESSION_STATE,    state);

        String authorizeUrl = authorizeEndpoint()
                + "?response_type=code"
                + "&client_id="              + encode(CLIENT_ID)
                + "&redirect_uri="           + encode(redirectUri())
                + "&scope="                  + encode(SCOPES)
                + "&code_challenge="         + encode(codeChallenge)
                + "&code_challenge_method=S256"
                + "&state="                  + encode(state);

        log.debug("[startAuth] Redirecting to authorization endpoint");
        return "redirect:" + authorizeUrl;
    }

    // -------------------------------------------------------------------------
    // Callback: validate state, exchange code for token
    // -------------------------------------------------------------------------
    @GetMapping("/callback")
    public String callback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description,
            HttpSession session,
            Model model) {

        if (error != null) {
            log.warn("[callback] OAuth2 error: {} — {}", error, error_description);
            model.addAttribute("error", error);
            model.addAttribute("errorDescription", error_description);
            return "error";
        }

        // CSRF state check
        String savedState = (String) session.getAttribute(SESSION_STATE);
        if (savedState == null || !savedState.equals(state)) {
            log.warn("[callback] State mismatch — possible CSRF attack");
            model.addAttribute("error", "invalid_state");
            model.addAttribute("errorDescription", "State mismatch. Please try signing in again.");
            return "error";
        }

        String codeVerifier = (String) session.getAttribute(SESSION_VERIFIER);
        if (codeVerifier == null) {
            model.addAttribute("error", "missing_verifier");
            model.addAttribute("errorDescription", "Session expired. Please try signing in again.");
            return "error";
        }

        try {
            String tokenResponse = exchangeCode(code, codeVerifier);
            JsonNode json = objectMapper.readTree(tokenResponse);

            if (json.has("error")) {
                log.warn("[callback] Token exchange failed: {}", json);
                model.addAttribute("error", json.path("error").asText());
                model.addAttribute("errorDescription", json.path("error_description").asText());
                return "error";
            }

            String accessToken  = json.path("access_token").asText(null);
            String refreshToken = json.path("refresh_token").asText(null);

            if (accessToken == null) {
                model.addAttribute("error", "no_token");
                model.addAttribute("errorDescription", "No access token in response: " + json);
                return "error";
            }

            TokenMeta meta = parseJwtMeta(accessToken, json);

            session.setAttribute(SESSION_TOKEN,      accessToken);
            session.setAttribute(SESSION_REFRESH,    refreshToken);
            session.setAttribute(SESSION_TOKEN_META, meta);
            session.removeAttribute(SESSION_VERIFIER);
            session.removeAttribute(SESSION_STATE);

            log.info("[callback] Token issued for subject: {}", meta.subject());

        } catch (Exception e) {
            log.error("[callback] Token exchange threw exception", e);
            model.addAttribute("error", "exchange_failed");
            model.addAttribute("errorDescription", e.getMessage());
            return "error";
        }

        return "redirect:/dashboard";
    }

    // -------------------------------------------------------------------------
    // Silent refresh: use the stored refresh token to get a new access token
    // Called by the dashboard JS before the access token expires
    // -------------------------------------------------------------------------
    @GetMapping("/refresh")
    public String refresh(HttpSession session, Model model) {
        String refreshToken = (String) session.getAttribute(SESSION_REFRESH);

        if (refreshToken == null) {
            log.warn("[refresh] No refresh token in session — restarting auth flow");
            return "redirect:/start-auth";
        }

        try {
            String body = "grant_type=refresh_token"
                    + "&refresh_token=" + encode(refreshToken)
                    + "&client_id="     + encode(CLIENT_ID);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenEndpoint()))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            JsonNode json = objectMapper.readTree(response.body());

            if (json.has("error")) {
                log.warn("[refresh] Refresh failed: {} — restarting auth flow", json);
                session.removeAttribute(SESSION_TOKEN);
                session.removeAttribute(SESSION_REFRESH);
                session.removeAttribute(SESSION_TOKEN_META);
                return "redirect:/start-auth";
            }

            String newAccessToken  = json.path("access_token").asText(null);
            String newRefreshToken = json.path("refresh_token").asText(refreshToken);

            if (newAccessToken != null) {
                TokenMeta meta = parseJwtMeta(newAccessToken, json);
                session.setAttribute(SESSION_TOKEN,      newAccessToken);
                session.setAttribute(SESSION_REFRESH,    newRefreshToken);
                session.setAttribute(SESSION_TOKEN_META, meta);
                log.info("[refresh] Token refreshed for subject: {}", meta.subject());
            }

        } catch (Exception e) {
            log.error("[refresh] Exception during token refresh", e);
            return "redirect:/start-auth";
        }

        return "redirect:/dashboard";
    }

    // -------------------------------------------------------------------------
    // Dashboard
    // -------------------------------------------------------------------------
    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication,
                            HttpSession session,
                            Model model) {

        model.addAttribute("email", authentication.getName());

        String    token = (String)    session.getAttribute(SESSION_TOKEN);
        TokenMeta meta  = (TokenMeta) session.getAttribute(SESSION_TOKEN_META);

        if (token != null && meta != null) {
            model.addAttribute("accessToken",  token);
            model.addAttribute("tokenExpiry",  meta.expiry());
            model.addAttribute("tokenScopes",  meta.scopes());
            model.addAttribute("tokenType",    "Bearer");
            model.addAttribute("tokenSubject", meta.subject());
            model.addAttribute("tokenExpiryEpoch", meta.expiryEpoch());
        }

        return "dashboard";
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private String exchangeCode(String code, String codeVerifier) throws Exception {
        String body = "grant_type=authorization_code"
                + "&code="          + encode(code)
                + "&redirect_uri="  + encode(redirectUri())
                + "&client_id="     + encode(CLIENT_ID)
                + "&code_verifier=" + encode(codeVerifier);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        return httpClient.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    private TokenMeta parseJwtMeta(String jwt, JsonNode tokenJson) {
        try {
            String[] parts   = jwt.split("\\.");
            String   payload = new String(
                    Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            JsonNode claims  = objectMapper.readTree(payload);

            long   expEpoch = claims.path("exp").asLong(0);
            String expiry   = expEpoch > 0
                    ? EXPIRY_FMT.format(Instant.ofEpochSecond(expEpoch)) + " UTC"
                    : "Unknown";

            String subject = claims.path("sub").asText(
                    tokenJson.path("sub").asText("unknown"));

            String scopeStr = claims.path("scope").asText(
                    tokenJson.path("scope").asText(""));
            List<String> scopes = scopeStr.isBlank()
                    ? List.of()
                    : Arrays.asList(scopeStr.split(" "));

            return new TokenMeta(expiry, scopes, subject, expEpoch);

        } catch (Exception e) {
            log.warn("[parseJwtMeta] Failed to parse JWT payload: {}", e.getMessage());
            return new TokenMeta("Unknown", List.of(), "unknown", 0);
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    // -------------------------------------------------------------------------
    // Token metadata record — now includes expiry epoch for JS countdown
    // -------------------------------------------------------------------------
    public record TokenMeta(
            String       expiry,
            List<String> scopes,
            String       subject,
            long         expiryEpoch
    ) {}
}