package com.trustguard.dto;

import java.time.Instant;

public record AccessCheckResponse(
        String requestId,
        String decision,
        String reason,
        String actor,
        String authenticatedPrincipal,
        boolean demoSimulation,
        String deviceUid,
        String sourceService,
        String targetService,
        String resourceKey,
        String nodeCode,
        int keyVersionUsed,
        Instant timestampUtc,
        String body,
        String ciphertextB64,
        String proofHex
) {
}
