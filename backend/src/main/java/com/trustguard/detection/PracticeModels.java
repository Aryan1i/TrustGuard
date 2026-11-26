package com.trustguard.detection;

import java.time.Instant;
import java.util.List;

public final class PracticeModels {

    private PracticeModels() {
    }

    public record PracticeEvent(
            String eventId,
            Instant eventTimeUtc,
            Instant receivedTimeUtc,
            long sourceClockOffsetMs,
            String actor,
            String sourceService,
            String targetService,
            String action,
            String roleBefore,
            String roleAfter,
            String outcome,
            String approvalId,
            String sessionId,
            String correlationId
    ) {
    }

    public record ApprovalChange(
            String approvalId,
            String approvedBy,
            String subject,
            String operation,
            String role,
            List<String> scope,
            Instant validFromUtc,
            Instant validUntilUtc,
            Instant effectiveAtUtc
    ) {
    }

    public record ExpectedLabel(
            String eventId,
            String label,
            String reason
    ) {
    }
}
