package com.caleb.backend.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;

@Controller
public class ConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    public ConsentController(RegisteredClientRepository registeredClientRepository,
                             OAuth2AuthorizationConsentService authorizationConsentService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationConsentService = authorizationConsentService;
    }

    @GetMapping("/oauth2/consent")
    public String consent(
            Principal principal,
            Model model,
            HttpServletRequest request,
            @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
            @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
            @RequestParam(OAuth2ParameterNames.STATE) String state,
            @RequestParam(name = OAuth2ParameterNames.REDIRECT_URI, required = false) String redirectUri) {

        // Extract raw (URL-encoded) state — preserves %3D
        String rawState = extractRawParam(request.getQueryString(), "state");
        String safeState = rawState != null ? rawState : state;

        // Extract PKCE params + redirect_uri from the original saved authorize request
        String codeChallenge = null;
        String codeChallengeMethod = "S256";
        String savedRedirectUri = redirectUri;

        try {
            SavedRequest savedReq = (SavedRequest)
                    request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST");
            if (savedReq != null) {
                String[] cc = savedReq.getParameterValues("code_challenge");
                String[] ccm = savedReq.getParameterValues("code_challenge_method");
                String[] ru = savedReq.getParameterValues("redirect_uri");
                if (cc != null && cc.length > 0) codeChallenge = cc[0];
                if (ccm != null && ccm.length > 0) codeChallengeMethod = ccm[0];
                if (ru != null && ru.length > 0) savedRedirectUri = ru[0];
            }
        } catch (Exception e) {
            System.out.println("Could not extract saved request: " + e.getMessage());
        }

        // Parse requested scopes
        Set<String> requestedScopes = new LinkedHashSet<>();
        for (String s : scope.split(" ")) {
            if (!s.isBlank()) requestedScopes.add(s);
        }

        // Look up client and existing consent
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        OAuth2AuthorizationConsent currentConsent = registeredClient != null
                ? authorizationConsentService.findById(registeredClient.getId(), principal.getName())
                : null;

        Set<String> previouslyApprovedScopes = new LinkedHashSet<>();
        Set<String> scopesToApprove = new LinkedHashSet<>();

        if (currentConsent != null) {
            currentConsent.getAuthorities().forEach(a -> {
                String authority = a.getAuthority();
                if (authority.startsWith("SCOPE_")) {
                    previouslyApprovedScopes.add(authority.substring(6));
                }
            });
        }

        for (String s : requestedScopes) {
            if (!previouslyApprovedScopes.contains(s)) scopesToApprove.add(s);
        }

        model.addAttribute("clientId", clientId);
        String decodedState = URLDecoder.decode(safeState, StandardCharsets.UTF_8);
        model.addAttribute("rawState", decodedState);        model.addAttribute("redirectUri", savedRedirectUri);
        model.addAttribute("codeChallenge", codeChallenge);
        model.addAttribute("codeChallengeMethod", codeChallengeMethod);
        model.addAttribute("clientName", registeredClient != null ? registeredClient.getClientName() : clientId);
        model.addAttribute("scopesToApprove", scopesToApprove);
        model.addAttribute("previouslyApprovedScopes", previouslyApprovedScopes);
        model.addAttribute("principalName", principal.getName());

        return "consent";
    }

    @GetMapping("/oauth2/consent/state")
    @ResponseBody
    public String getConsentState(HttpServletRequest request) {
        return "";  // kept for compatibility, no longer used
    }

    private String extractRawParam(String queryString, String paramName) {
        if (queryString == null) return null;
        String prefix = paramName + "=";
        for (String part : queryString.split("&")) {
            if (part.startsWith(prefix)) {
                return part.substring(prefix.length());
            }
        }
        return null;
    }
}