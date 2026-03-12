package com.caleb.backend.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO for the registration form.
 * Validation is enforced via Spring's @Valid annotation in the controller.
 */
public class RegistrationRequest {

    @NotBlank(message = "Full name is required")
    @Size(max = 100, message = "Full name must be under 100 characters")
    private String fullName;

    @NotBlank(message = "Email is required")
    @Email(message = "Must be a valid email address")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
    private String password;

    @NotBlank(message = "Please confirm your password")
    private String confirmPassword;

    // -------------------------------------------------------------------------
    // Getters / Setters
    // -------------------------------------------------------------------------

    public String getFullName()        { return fullName; }
    public void setFullName(String v)  { this.fullName = v; }

    public String getEmail()           { return email; }
    public void setEmail(String v)     { this.email = v; }

    public String getPassword()        { return password; }
    public void setPassword(String v)  { this.password = v; }

    public String getConfirmPassword()       { return confirmPassword; }
    public void setConfirmPassword(String v) { this.confirmPassword = v; }

    public boolean passwordsMatch() {
        return password != null && password.equals(confirmPassword);
    }
}