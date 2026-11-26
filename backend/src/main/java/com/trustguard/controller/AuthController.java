package com.trustguard.controller;

import com.trustguard.audit.AuditLogService;
import com.trustguard.dto.AuthResponse;
import com.trustguard.dto.LoginRequest;
import com.trustguard.entity.UserEntity;
import com.trustguard.exception.ResourceNotFoundException;
import com.trustguard.repository.UserRepository;
import com.trustguard.security.JwtService;
import com.trustguard.security.SecurityUtils;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuditLogService auditLogService;

    public AuthController(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            JwtService jwtService,
            AuditLogService auditLogService
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.auditLogService = auditLogService;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
                "status", "UP",
                "service", "trustguard-backend",
                "timestamp", Instant.now()
        );
    }

    @PostMapping("/auth/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username().trim(), request.password())
        );
        UserEntity user = userRepository.findByUsername(request.username().trim())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        JwtService.TokenResult token = jwtService.generateToken(user.getUsername(), user.getRole());
        auditLogService.appendEvent(
                user.getUsername(),
                "AUTH_SIGN_IN",
                "identity",
                "Authenticated JWT session issued for synthetic identity " + user.getUsername() + " (" + user.getRole() + ")"
        );
        return new AuthResponse(
                token.token(),
                "Bearer",
                user.getUsername(),
                user.getDisplayName(),
                user.getRole(),
                token.expiresAt(),
                true
        );
    }

    @GetMapping("/auth/me")
    public Map<String, Object> me() {
        String username = SecurityUtils.currentUsername();
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return Map.of(
                "username", user.getUsername(),
                "displayName", user.getDisplayName(),
                "role", user.getRole(),
                "email", user.getEmail(),
                "syntheticDemoIdentity", true
        );
    }
}
