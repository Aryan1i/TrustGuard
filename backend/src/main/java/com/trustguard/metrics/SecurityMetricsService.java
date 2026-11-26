package com.trustguard.metrics;

import com.trustguard.audit.AuditLogService;
import com.trustguard.detection.DetectionOrchestrationService;
import com.trustguard.dto.DetectionEvaluationResponse;
import com.trustguard.dto.DetectionEvaluationResponse.EvaluationMetricsDto;
import com.trustguard.dto.KeyVersionResponse;
import com.trustguard.dto.SecurityMetricsResponse;
import com.trustguard.entity.RevocationEntity;
import com.trustguard.entity.SecurityAlertEntity;
import com.trustguard.entity.SimulatedNodeEntity;
import com.trustguard.repository.AccessEventRepository;
import com.trustguard.repository.RevocationRepository;
import com.trustguard.repository.SecurityAlertRepository;
import com.trustguard.repository.SimulatedNodeRepository;
import com.trustguard.security.SecurityUtils;
import com.trustguard.service.KeyManagementService;
import com.trustguard.service.SessionService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

@Service
public class SecurityMetricsService {

    public static final String SAMPLE_CAVEAT =
            "The 22-event public practice dataset is only a functional example and cannot establish "
            + "production detection accuracy, false-positive rate, or throughput.";

    private final DetectionOrchestrationService detectionService;
    private final RevocationRepository revocationRepository;
    private final SimulatedNodeRepository nodeRepository;
    private final KeyManagementService keyManagementService;
    private final AuditLogService auditLogService;
    private final SecurityAlertRepository alertRepository;
    private final AccessEventRepository accessEventRepository;
    private final SessionService sessionService;

    public SecurityMetricsService(
            DetectionOrchestrationService detectionService,
            RevocationRepository revocationRepository,
            SimulatedNodeRepository nodeRepository,
            KeyManagementService keyManagementService,
            AuditLogService auditLogService,
            SecurityAlertRepository alertRepository,
            AccessEventRepository accessEventRepository,
            SessionService sessionService
    ) {
        this.detectionService = detectionService;
        this.revocationRepository = revocationRepository;
        this.nodeRepository = nodeRepository;
        this.keyManagementService = keyManagementService;
        this.auditLogService = auditLogService;
        this.alertRepository = alertRepository;
        this.accessEventRepository = accessEventRepository;
        this.sessionService = sessionService;
    }

    public SecurityMetricsResponse calculateMetrics() {
        boolean admin = SecurityUtils.isAdmin();
        String caller = admin ? null : SecurityUtils.currentUsername();

        DetectionEvaluationResponse practiceEval = detectionService.getLatestPracticeEvaluation();
        EvaluationMetricsDto eval = practiceEval.postDetectionEvaluation();

        List<Long> latencies = alertRepository.findAllByOrderByDetectedAtDesc().stream()
                .filter(alert -> admin || caller.equals(alert.getActor()))
                .map(SecurityAlertEntity::getDetectionLatencyMs)
                .sorted()
                .toList();
        double medianLatencyMs = 0.0;
        if (!latencies.isEmpty()) {
            int n = latencies.size();
            medianLatencyMs = (n % 2 == 1)
                    ? latencies.get(n / 2)
                    : (latencies.get(n / 2 - 1) + latencies.get(n / 2)) / 2.0;
        }

        Long lastRevocationLatencyMs = revocationRepository.findTopByOrderByRevocationVersionDesc()
                .map(RevocationEntity::getPropagationLatencyMs)
                .orElse(null);

        List<SimulatedNodeEntity> nodes = nodeRepository.findAllByOrderByIdAsc();
        List<KeyVersionResponse> keys = keyManagementService.listKeys();
        int ackedCount = 0;
        if (!keys.isEmpty()) {
            ackedCount = (int) keys.get(0).acknowledgements().stream()
                    .filter(a -> "ACKNOWLEDGED".equals(a.ackStatus()))
                    .count();
        }

        int liveAccessCount = admin
                ? (int) accessEventRepository.count()
                : accessEventRepository.findByActorUsernameOrAuthenticatedPrincipal(caller, caller).size();

        return new SecurityMetricsResponse(
                practiceEval.datasetSource(),
                eval.sampleSize(),
                liveAccessCount,
                eval.precision(),
                eval.recall(),
                eval.f1Score(),
                medianLatencyMs,
                eval.falseAlertsPer1000Benign(),
                lastRevocationLatencyMs,
                ackedCount,
                nodes.size(),
                auditLogService.getVerificationFailuresCount(),
                SAMPLE_CAVEAT,
                sessionService.getLastTestResults().isEmpty() ? Collections.emptyList() : sessionService.getLastTestResults(),
                Instant.now()
        );
    }
}
