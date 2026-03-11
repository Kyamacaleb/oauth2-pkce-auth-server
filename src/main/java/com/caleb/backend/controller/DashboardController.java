package com.caleb.backend.controller;

import com.caleb.backend.model.AccessToken;
import com.caleb.backend.model.User;
import com.caleb.backend.repository.AccessTokenRepository;
import com.caleb.backend.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

@Controller
public class DashboardController {

    private final UserRepository userRepository;
    private final AccessTokenRepository accessTokenRepository;

    public DashboardController(UserRepository userRepository,
                               AccessTokenRepository accessTokenRepository) {
        this.userRepository = userRepository;
        this.accessTokenRepository = accessTokenRepository;
    }

    /**
     * Dashboard — shown after successful login.
     * If an access token was just issued (passed as query param from the callback),
     * it's looked up and its details are shown.
     */
    @GetMapping("/dashboard")
    public String dashboard(
            Authentication authentication,
            @RequestParam(required = false) String token,
            Model model) {

        String email = authentication.getName();
        Optional<User> userOpt = userRepository.findByEmail(email);
        userOpt.ifPresent(user -> {
            model.addAttribute("fullName", user.getFullName() != null ? user.getFullName() : email);
            model.addAttribute("email", user.getEmail());
        });

        // If a token was just issued (redirect from /callback?token=...), show its details
        if (token != null) {
            accessTokenRepository.findByTokenValue(token).ifPresent(at -> {
                model.addAttribute("accessToken", at.getTokenValue());
                model.addAttribute("tokenExpiry", formatExpiry(at.getExpiresAt()));
                model.addAttribute("tokenScopes", at.getScopeList());
                model.addAttribute("tokenRevoked", at.getRevoked());
                model.addAttribute("tokenType", "Bearer");
            });
        }

        model.addAttribute("currentYear", LocalDateTime.now().getYear());
        return "dashboard";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return "redirect:/login?logout";
    }

    private String formatExpiry(LocalDateTime expiry) {
        if (expiry == null) return "Unknown";
        return expiry.format(DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm:ss"));
    }
}