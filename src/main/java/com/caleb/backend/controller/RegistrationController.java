package com.caleb.backend.controller;

import com.caleb.backend.dto.RegistrationRequest;
import com.caleb.backend.model.User;
import com.caleb.backend.repository.UserRepository;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Handles user self-registration.
 *
 * GET  /register → shows the sign-up form
 * POST /register → validates, creates user, redirects to login
 *
 * Validations performed:
 *   • JSR-380 field constraints (blank, email format, size)
 *   • Password confirmation match
 *   • Duplicate email check
 */
@Controller
public class RegistrationController {

    private static final Logger log = LoggerFactory.getLogger(RegistrationController.class);

    private final UserRepository  userRepository;
    private final PasswordEncoder passwordEncoder;

    public RegistrationController(UserRepository userRepository,
                                  PasswordEncoder passwordEncoder) {
        this.userRepository  = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/register")
    public String showForm(Model model) {
        model.addAttribute("form", new RegistrationRequest());
        return "register";
    }

    @PostMapping("/register")
    public String register(
            @Valid @ModelAttribute("form") RegistrationRequest form,
            BindingResult bindingResult,
            Model model) {

        // ── Field-level validation errors ──
        if (bindingResult.hasErrors()) {
            return "register";
        }

        // ── Password confirmation ──
        if (!form.passwordsMatch()) {
            model.addAttribute("passwordMismatch", true);
            return "register";
        }

        // ── Duplicate email ──
        if (userRepository.existsByEmail(form.getEmail().toLowerCase().trim())) {
            model.addAttribute("emailTaken", true);
            return "register";
        }

        // ── Create user ──
        User user = new User();
        user.setFullName(form.getFullName().trim());
        user.setEmail(form.getEmail().toLowerCase().trim());
        user.setPassword(passwordEncoder.encode(form.getPassword()));
        user.setEnabled(true);
        userRepository.save(user);

        log.info("[Registration] New user registered: {}", user.getEmail());

        return "redirect:/login?registered";
    }
}