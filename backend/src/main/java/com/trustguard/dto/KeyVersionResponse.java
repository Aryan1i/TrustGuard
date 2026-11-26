package com.trustguard.dto;

import java.time.Instant;
import java.util.List;

public record KeyVersionResponse(
        Long id,
        String keyAlias,
        int versionNumber,
        String algorithm,
        String status,
        String publicKeyFingerprint,
        int gracePeriodSeconds,
        Instant createdAt,
        Instant distributedAt,
        Instant committedAt,
        Instant activationTime,
        Instant graceUntil,
        Instant cutoffTime,
        String failureReason,
        List<NodeAckDto> acknowledgements
) {
    public record NodeAckDto(
            String nodeCode,
            String nodeName,
            String ackStatus,
            Instant acknowledgedAt,
            String detailMessage
    ) {
    }
}
