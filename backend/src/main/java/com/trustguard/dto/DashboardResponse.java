package com.trustguard.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record DashboardResponse(
        long activeUsers,
        long activeDevices,
        long revokedDevices,
        int activeKeyVersion,
        String activeKeyAlgorithm,
        String activeKeyStatus,
        int totalNodes,
        int acknowledgedNodes,
        long latestRevocationVersion,
        Long lastRevocationPropagationMs,
        boolean auditChainVerified,
        long auditEntryCount,
        long openAlertCount,
        Map<String, Long> openAlertsBySeverity,
        long allowedAccessCount,
        long deniedAccessCount,
        List<Map<String, Object>> recentEvents,
        SecurityMetricsResponse metricsSummary,
        Instant generatedAt
) {
}
