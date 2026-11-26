package com.trustguard.dto;

import java.time.Instant;
import java.util.List;

public record AuditVerifyResponse(
        boolean valid,
        int totalEntries,
        int checkedEntries,
        Long firstMismatchSeq,
        String firstMismatchEventId,
        String expectedHash,
        String actualHash,
        int verificationFailuresCount,
        String message,
        String limitationNotice,
        Instant verifiedAt
) {
    public record AuditEntryDto(
            Long id,
            String eventId,
            long seqNumber,
            String actor,
            String action,
            String resource,
            String detail,
            Instant eventTimestampUtc,
            String prevHash,
            String currentHash
    ) {
    }

    public record AuditListResponse(
            List<AuditEntryDto> entries,
            AuditVerifyResponse latestVerification
    ) {
    }
}
