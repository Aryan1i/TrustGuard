package com.trustguard.dto;

import java.time.Instant;

public record BackupResponse(
        String backupId,
        String createdBy,
        int keyVersionNumber,
        long revocationVersion,
        String checksumSha256,
        String verificationStatus,
        String restoreStatus,
        int itemCount,
        Instant createdAt,
        Instant verifiedAt,
        Instant restoredAt,
        String message
) {
}
