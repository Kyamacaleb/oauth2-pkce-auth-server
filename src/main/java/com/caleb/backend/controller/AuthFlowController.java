package com.caleb.backend.controller;

import com.caleb.backend.util.PKCEUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
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
 * Handles the entire OAuth2 + PKCE flow server-side so the user never
 * has to construct URLs or run curl commands manually.
 */
@Controller
public class AuthFlowController {

    private static final String CLIENT_ID    = "frontend-app";
    private static final String REDIRECT_URI = "http://localhost:8080/callback";
    private static final String SCOPES       = "openid read:profile read:email";
    private static final String SESSION_VERIFIER = "pkce_code_verifier";
    private static final String SESSION_STATE    = "oauth2_state";
    private static final String SESSION_TOKEN    = "access_token";
    private static final String SESSION_TOKEN_META = "access_token_meta";
    private static final DateTimeFormatter EXPIRY_FMT =
            DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm:ss").withZone(ZoneId.of("UTC"));

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient   httpClient   = HttpClient.newHttpClient();

    @GetMapping("/")
    public String welcomePage() {
        return "welcome";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/start-auth")
    public String startAuth(HttpSession session) {
        String codeVerifier    = PKCEUtil.generateCodeVerifier();
        String codeChallenge   = PKCEUtil.generateCodeChallenge(codeVerifier);
        String state           = UUID.randomUUID().toString();

        // Persist in session for later use in /callback
        session.setAttribute(SESSION_VERIFIER, codeVerifier);
        session.setAttribute(SESSION_STATE,    state);

        String authorizeUrl = "http://localhost:8080/oauth2/authorize"
                + "?response_type=code"
                + "&client_id="             + encode(CLIENT_ID)
                + "&redirect_uri="          + encode(REDIRECT_URI)
                + "&scope="                 + encode(SCOPES)
                + "&code_challenge="        + encode(codeChallenge)
                + "&code_challenge_method=S256"
                + "&state="                 + encode(state);

        return "redirect:" + authorizeUrl;
    }

    @GetMapping("/callback")
    public String callback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description,
            HttpSession session,
            Model model) {

        // Handle OAuth2 errors
        if (error != null) {
            model.addAttribute("error", error);
            model.addAttribute("errorDescription", error_description);
            return "error";
        }

        // Validate state to prevent CSRF
        String savedState = (String) session.getAttribute(SESSION_STATE);
        if (savedState == null || !savedState.equals(state)) {
            model.addAttribute("error", "invalid_state");
            model.addAttribute("errorDescription", "State mismatch — possible CSRF attack.");
            return "error";
        }

        // Retrieve verifier
        String codeVerifier = (String) session.getAttribute(SESSION_VERIFIER);
        if (codeVerifier == null) {
            model.addAttribute("error", "missing_verifier");
            model.addAttribute("errorDescription", "PKCE code verifier not found in session.");
            return "error";
        }

        // Exchange code for token
        try {
            String tokenResponse = exchangeCodeForToken(code, codeVerifier);
            JsonNode json = objectMapper.readTree(tokenResponse);

            String accessToken = json.path("access_token").asText(null);
            if (accessToken == null) {
                model.addAttribute("error", "token_error");
                model.addAttribute("errorDescription", json.toString());
                return "error";
            }

            // Parse JWT payload for metadata (no signature verification needed here —
            // the Authorization Server already validated it)
            TokenMeta meta = parseJwtMeta(accessToken, json);

            // Store in session
            session.setAttribute(SESSION_TOKEN,      accessToken);
            session.setAttribute(SESSION_TOKEN_META, meta);

            // Clean up PKCE state
            session.removeAttribute(SESSION_VERIFIER);
            session.removeAttribute(SESSION_STATE);

        } catch (Exception e) {
            model.addAttribute("error", "exchange_failed");
            model.addAttribute("errorDescription", e.getMessage());
            return "error";
        }

        return "redirect:/dashboard";
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication,
                            HttpSession session,
                            Model model) {

        model.addAttribute("email", authentication.getName());

        String token = (String) session.getAttribute(SESSION_TOKEN);
        TokenMeta meta = (TokenMeta) session.getAttribute(SESSION_TOKEN_META);

        if (token != null && meta != null) {
            model.addAttribute("accessToken",  token);
            model.addAttribute("tokenExpiry",  meta.expiry());
            model.addAttribute("tokenScopes",  meta.scopes());
            model.addAttribute("tokenType",    "Bearer");
            model.addAttribute("tokenSubject", meta.subject());
        }

        return "dashboard";
    }

    private String exchangeCodeForToken(String code, String codeVerifier) throws Exception {
        String body = "grant_type=authorization_code"
                + "&code="          + encode(code)
                + "&redirect_uri="  + encode(REDIRECT_URI)
                + "&client_id="     + encode(CLIENT_ID)
                + "&code_verifier=" + encode(codeVerifier);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8080/oauth2/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response =
                httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        return response.body();
    }

    private TokenMeta parseJwtMeta(String jwt, JsonNode tokenJson) {
        try {
            String[] parts   = jwt.split("\\.");
            String   payload = new String(
                    Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            JsonNode claims  = objectMapper.readTree(payload);

            long exp = claims.path("exp").asLong(0);
            String expiry = exp > 0
                    ? EXPIRY_FMT.format(Instant.ofEpochSecond(exp)) + " UTC"
                    : "Unknown";

            String subject = claims.path("sub").asText(
                    tokenJson.path("sub").asText("unknown"));

            // Scopes can come from the JWT claim or the token response
            List<String> scopes;
            String scopeStr = claims.path("scope").asText(
                    tokenJson.path("scope").asText(""));
            scopes = scopeStr.isBlank()
                    ? List.of()
                    : Arrays.asList(scopeStr.split(" "));

            return new TokenMeta(expiry, scopes, subject);

        } catch (Exception e) {
            return new TokenMeta("Unknown", List.of(), "unknown");
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    public record TokenMeta(String expiry, List<String> scopes, String subject) {}
}