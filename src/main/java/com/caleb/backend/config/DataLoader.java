package com.caleb.backend.config;

import com.caleb.backend.model.User;
import com.caleb.backend.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Seeds the database with a default user on startup.
 */
@Component
public class DataLoader implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataLoader(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (!userRepository.existsByEmail("user@example.com")) {
            User user = new User();
            user.setEmail("user@example.com");
            user.setPassword(passwordEncoder.encode("Password123!"));
            user.setFullName("Default User");
            user.setEnabled(true);
            userRepository.save(user);
            System.out.println("=================================================");
            System.out.println("Default user created:");
            System.out.println("  Email   : user@example.com");
            System.out.println("  Password: Password123!");
            System.out.println("=================================================");
        }
    }
}