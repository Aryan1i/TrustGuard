package com.trustguard.dto;

import java.time.Instant;

public record AuthResponse(
        String token,
        String tokenType,
        String username,
        String displayName,
        String role,
        Instant expiresAt,
        boolean syntheticDemoIdentity
) {
}
