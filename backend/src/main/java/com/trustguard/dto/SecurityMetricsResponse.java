package com.trustguard.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record SecurityMetricsResponse(
        String datasetSource,
        int practiceSampleSize,
        int liveAccessSampleSize,
        double precision,
        double recall,
        double f1Score,
        double medianAlertLatencyMs,
        double falseAlertsPer1000Benign,
        Long revocationToLastNodeLatencyMs,
        int acknowledgedNodesCount,
        int totalNodesCount,
        int auditVerificationFailures,
        String sampleCaveat,
        List<Map<String, Object>> sessionAndDeliveryTests,
        Instant calculatedAt
) {
}
