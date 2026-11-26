package com.trustguard.controller;

import com.trustguard.audit.AuditLogService;
import com.trustguard.dto.AuthResponse;
import com.trustguard.dto.LoginRequest;
import com.trustguard.entity.UserEntity;
import com.trustguard.exception.RateLimitExceededException;
import com.trustguard.exception.ResourceNotFoundException;
import com.trustguard.repository.UserRepository;
import com.trustguard.security.AuthRateLimiter;
import com.trustguard.security.JwtService;
import com.trustguard.security.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.transaction.annotation.Transactional;
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
    private final AuthRateLimiter authRateLimiter;

    public AuthController(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            JwtService jwtService,
            AuditLogService auditLogService,
            AuthRateLimiter authRateLimiter
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.auditLogService = auditLogService;
        this.authRateLimiter = authRateLimiter;
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
    public AuthResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        String trimmedUsername = request.username().trim();
        String clientIp = httpRequest != null ? httpRequest.getRemoteAddr() : "unknown";

        try {
            authRateLimiter.checkAllowed(trimmedUsername, clientIp);
        } catch (RateLimitExceededException ex) {
            auditLogService.appendEvent(
                    trimmedUsername.isEmpty() ? "anonymous" : trimmedUsername,
                    "AUTH_RATE_LIMITED",
                    "identity",
                    "Login temporarily throttled due to repeated authentication failures from ip=" + clientIp
            );
            throw ex;
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(trimmedUsername, request.password())
            );
        } catch (AuthenticationException ex) {
            authRateLimiter.recordFailure(trimmedUsername, clientIp);
            throw ex;
        }

        authRateLimiter.recordSuccess(trimmedUsername, clientIp);
        UserEntity user = userRepository.findByUsername(trimmedUsername)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        JwtService.TokenResult token = jwtService.generateToken(user.getUsername(), user.getRole(), user.getTokenVersion());
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

    @PostMapping("/auth/logout")
    @Transactional
    public Map<String, Object> logout() {
        String username = SecurityUtils.currentUsername();
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        user.setTokenVersion(user.getTokenVersion() + 1L);
        userRepository.save(user);
        auditLogService.appendEvent(
                username,
                "AUTH_SIGN_OUT",
                "identity",
                "Signed out caller and invalidated active JWTs (tokenVersion=" + user.getTokenVersion() + ")"
        );
        return Map.of(
                "loggedOut", true,
                "username", user.getUsername(),
                "tokenVersion", user.getTokenVersion()
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
