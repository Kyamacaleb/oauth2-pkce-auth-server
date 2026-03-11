package com.caleb.backend.controller;

import com.caleb.backend.dto.AppRegistrationRequest;
import com.caleb.backend.dto.AppRegistrationResponse;
import com.caleb.backend.service.AppRegistrationService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/apps")
public class AppRegistrationController {

    private final AppRegistrationService appRegistrationService;

    public AppRegistrationController(AppRegistrationService appRegistrationService) {
        this.appRegistrationService = appRegistrationService;
    }

    /**
     * Register a new OAuth2 app via curl:
     */
    @PostMapping
    public ResponseEntity<AppRegistrationResponse> registerApp(
            @Valid @RequestBody AppRegistrationRequest request) {
        AppRegistrationResponse response = appRegistrationService.registerApp(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{clientId}")
    public ResponseEntity<AppRegistrationResponse> getApp(@PathVariable String clientId) {
        return appRegistrationService.findByClientId(clientId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}