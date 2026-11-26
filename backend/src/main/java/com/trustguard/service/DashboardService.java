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
        boolean admin = com.trustguard.security.SecurityUtils.isAdmin();
        String caller = admin ? null : com.trustguard.security.SecurityUtils.currentUsername();

        long activeUsers = admin
                ? userRepository.countByActiveTrue()
                : userRepository.findByUsername(caller).filter(u -> u.isActive()).map(u -> 1L).orElse(0L);
        long activeDevices;
        long revokedDevices;
        if (admin) {
            activeDevices = deviceRepository.countByStatus("ACTIVE");
            revokedDevices = deviceRepository.countByStatus("REVOKED");
        } else {
            var callerDevices = deviceRepository.findByOwnerUsernameOrderByEnrolledAtDesc(caller);
            activeDevices = callerDevices.stream().filter(d -> "ACTIVE".equals(d.getStatus())).count();
            revokedDevices = callerDevices.stream().filter(d -> "REVOKED".equals(d.getStatus())).count();
        }

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
        List<com.trustguard.entity.AuditLogEntity> auditRows = auditLogRepository.findAllByOrderBySeqNumberDesc();
        List<com.trustguard.entity.AuditLogEntity> scopedAuditRows = admin
                ? auditRows
                : auditRows.stream().filter(a -> caller.equals(a.getActor())).toList();
        long auditCount = admin ? auditLogRepository.count() : scopedAuditRows.size();

        List<com.trustguard.entity.SecurityAlertEntity> scopedOpenAlerts = admin
                ? List.of()
                : alertRepository.findAllByOrderByDetectedAtDesc().stream()
                        .filter(a -> !a.isResolved() && caller.equals(a.getActor()))
                        .toList();
        Map<String, Long> alertsBySeverity = new LinkedHashMap<>();
        for (String severity : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) {
            long count = admin
                    ? alertRepository.countBySeverityAndResolvedFalse(severity)
                    : scopedOpenAlerts.stream().filter(a -> severity.equals(a.getSeverity())).count();
            alertsBySeverity.put(severity, count);
        }
        long openAlertCount = admin
                ? alertRepository.countByResolvedFalse()
                : scopedOpenAlerts.size();

        long allowedCount;
        long deniedCount;
        if (admin) {
            allowedCount = accessEventRepository.countByDecision("ALLOW");
            deniedCount = accessEventRepository.countByDecision("DENY");
        } else {
            var callerAccessEvents = accessEventRepository.findByActorUsernameOrAuthenticatedPrincipal(caller, caller);
            allowedCount = callerAccessEvents.stream().filter(e -> "ALLOW".equals(e.getDecision())).count();
            deniedCount = callerAccessEvents.stream().filter(e -> "DENY".equals(e.getDecision())).count();
        }

        List<Map<String, Object>> recentEvents = scopedAuditRows.stream()
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
                openAlertCount,
                alertsBySeverity,
                allowedCount,
                deniedCount,
                recentEvents,
                metricsSummary,
                Instant.now()
        );
    }
}
