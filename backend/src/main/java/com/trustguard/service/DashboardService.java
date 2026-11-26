package com.trustguard.service;

import com.trustguard.audit.AuditLogService;
import com.trustguard.dto.AuditVerifyResponse;
import com.trustguard.dto.DashboardResponse;
import com.trustguard.dto.KeyVersionResponse;
import com.trustguard.dto.SecurityMetricsResponse;
import com.trustguard.entity.KeyVersionEntity;
import com.trustguard.entity.RevocationEntity;
import com.trustguard.metrics.SecurityMetricsService;
import com.trustguard.repository.AccessEventRepository;
import com.trustguard.repository.AuditLogRepository;
import com.trustguard.repository.DeviceRepository;
import com.trustguard.repository.RevocationRepository;
import com.trustguard.repository.SecurityAlertRepository;
import com.trustguard.repository.SimulatedNodeRepository;
import com.trustguard.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class DashboardService {

    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final KeyManagementService keyManagementService;
    private final SimulatedNodeRepository nodeRepository;
    private final RevocationRepository revocationRepository;
    private final AuditLogService auditLogService;
    private final AuditLogRepository auditLogRepository;
    private final SecurityAlertRepository alertRepository;
    private final AccessEventRepository accessEventRepository;
    private final SecurityMetricsService metricsService;

    public DashboardService(
            UserRepository userRepository,
            DeviceRepository deviceRepository,
            KeyManagementService keyManagementService,
            SimulatedNodeRepository nodeRepository,
            RevocationRepository revocationRepository,
            AuditLogService auditLogService,
            AuditLogRepository auditLogRepository,
            SecurityAlertRepository alertRepository,
            AccessEventRepository accessEventRepository,
            SecurityMetricsService metricsService
    ) {
        this.userRepository = userRepository;
        this.deviceRepository = deviceRepository;
        this.keyManagementService = keyManagementService;
        this.nodeRepository = nodeRepository;
        this.revocationRepository = revocationRepository;
        this.auditLogService = auditLogService;
        this.auditLogRepository = auditLogRepository;
        this.alertRepository = alertRepository;
        this.accessEventRepository = accessEventRepository;
        this.metricsService = metricsService;
    }

    public DashboardResponse getDashboardSummary() {
        long activeUsers = userRepository.countByActiveTrue();
        long activeDevices = deviceRepository.countByStatus("ACTIVE");
        long revokedDevices = deviceRepository.countByStatus("REVOKED");

        KeyVersionEntity activeKey = keyManagementService.getActiveCommittedKey();
        List<KeyVersionResponse> keys = keyManagementService.listKeys();
        int totalNodes = (int) nodeRepository.count();
        int acknowledgedNodes = keys.isEmpty() ? 0 : (int) keys.get(0).acknowledgements().stream()
                .filter(a -> "ACKNOWLEDGED".equals(a.ackStatus()))
                .count();

        RevocationEntity latestRevocation = revocationRepository.findTopByOrderByRevocationVersionDesc().orElse(null);
        long revVersion = latestRevocation != null ? latestRevocation.getRevocationVersion() : 0L;
        Long revLatency = latestRevocation != null ? latestRevocation.getPropagationLatencyMs() : null;

        AuditVerifyResponse auditStatus = auditLogService.verifyChainReadOnly();
        long auditCount = auditLogRepository.count();

        Map<String, Long> alertsBySeverity = new LinkedHashMap<>();
        alertsBySeverity.put("CRITICAL", alertRepository.countBySeverityAndResolvedFalse("CRITICAL"));
        alertsBySeverity.put("HIGH", alertRepository.countBySeverityAndResolvedFalse("HIGH"));
        alertsBySeverity.put("MEDIUM", alertRepository.countBySeverityAndResolvedFalse("MEDIUM"));
        alertsBySeverity.put("LOW", alertRepository.countBySeverityAndResolvedFalse("LOW"));
        alertsBySeverity.put("INFO", alertRepository.countBySeverityAndResolvedFalse("INFO"));

        long allowedCount = accessEventRepository.countByDecision("ALLOW");
        long deniedCount = accessEventRepository.countByDecision("DENY");

        List<Map<String, Object>> recentEvents = auditLogRepository.findAllByOrderBySeqNumberDesc().stream()
                .limit(8)
                .map(a -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("eventId", a.getEventId());
                    m.put("seqNumber", a.getSeqNumber());
                    m.put("actor", a.getActor());
                    m.put("action", a.getAction());
                    m.put("resource", a.getResource());
                    m.put("detail", a.getDetail());
                    m.put("timestampUtc", a.getEventTimestampUtc());
                    return m;
                })
                .toList();

        SecurityMetricsResponse metricsSummary = metricsService.calculateMetrics();

        return new DashboardResponse(
                activeUsers,
                activeDevices,
                revokedDevices,
                activeKey.getVersionNumber(),
                activeKey.getAlgorithm(),
                activeKey.getStatus(),
                totalNodes,
                acknowledgedNodes,
                revVersion,
                revLatency,
                auditStatus.valid(),
                auditCount,
                alertRepository.countByResolvedFalse(),
                alertsBySeverity,
                allowedCount,
                deniedCount,
                recentEvents,
                metricsSummary,
                Instant.now()
        );
    }
}
