package com.trustguard.dto;

import java.time.Instant;

public record DeviceResponse(
        Long id,
        String deviceUid,
        String ownerUsername,
        String ownerDisplayName,
        String deviceName,
        String publicKeyFingerprint,
        String keyAlgorithm,
        String status,
        Instant enrolledAt,
        Instant lastSeenAt,
        Instant revokedAt,
        Long replacedByDeviceId
) {
}
