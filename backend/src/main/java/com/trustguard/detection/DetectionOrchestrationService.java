package com.trustguard.detection;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.audit.AuditLogService;
import com.trustguard.detection.DeterministicDetectionEngine.EngineOutput;
import com.trustguard.detection.PracticeModels.ApprovalChange;
import com.trustguard.detection.PracticeModels.ExpectedLabel;
import com.trustguard.detection.PracticeModels.PracticeEvent;
import com.trustguard.dto.DetectionEvaluationResponse;
import com.trustguard.dto.DetectionEvaluationResponse.AlertDto;
import com.trustguard.dto.DetectionEvaluationResponse.EvaluationMetricsDto;
import com.trustguard.entity.SecurityAlertEntity;
import com.trustguard.repository.SecurityAlertRepository;
import com.trustguard.security.SecurityUtils;
import com.trustguard.util.CanonicalJsonUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
public class DetectionOrchestrationService {

    public static final String PRACTICE_SOURCE = "PRACTICE_22_EVENTS";
    public static final String PRACTICE_LIMITATION =
            "The 22-event public practice dataset (events.csv + approvals.json) is a functional demonstration only. "
            + "It cannot establish production detection accuracy, false-positive rates, or throughput. "
            + "Ground-truth labels.csv was NOT read by the detector and was applied strictly post-detection.";

    private final PracticeDatasetLoader datasetLoader;
    private final DeterministicDetectionEngine engine;
    private final PracticeEvaluator evaluator;
    private final SecurityAlertRepository alertRepository;
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;

    private volatile DetectionEvaluationResponse lastPracticeRun;

    public DetectionOrchestrationService(
            PracticeDatasetLoader datasetLoader,
            DeterministicDetectionEngine engine,
            PracticeEvaluator evaluator,
            SecurityAlertRepository alertRepository,
            AuditLogService auditLogService,
            ObjectMapper objectMapper
    ) {
        this.datasetLoader = datasetLoader;
        this.engine = engine;
        this.evaluator = evaluator;
        this.alertRepository = alertRepository;
        this.auditLogService = auditLogService;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public DetectionEvaluationResponse evaluatePracticeDataset() {
        List<PracticeEvent> events = datasetLoader.loadEvents();
        List<ApprovalChange> approvals = datasetLoader.loadApprovals();

        long startNs = System.nanoTime();
        EngineOutput output = engine.evaluatePracticeEvents(events, approvals);
        long elapsedMs = Math.max(1L, (System.nanoTime() - startNs) / 1_000_000L);

        // Only load ground-truth labels AFTER detection has finished
        List<ExpectedLabel> labels = datasetLoader.loadLabelsOnlyForPostEvaluation();
        EvaluationMetricsDto metrics = evaluator.evaluateAgainstLabels(output.classifiedEvents(), labels);

        // Replace previous practice alerts cleanly and flush before re-inserting deterministic alertUids
        List<SecurityAlertEntity> existingPractice = alertRepository.findByDatasetSourceOrderByIdAsc(PRACTICE_SOURCE);
        if (!existingPractice.isEmpty()) {
            alertRepository.deleteAllInBatch(existingPractice);
            alertRepository.flush();
        }

        Instant detectedAt = Instant.now();
        for (AlertDto dto : output.alerts()) {
            SecurityAlertEntity entity = new SecurityAlertEntity();
            entity.setAlertUid(dto.alertUid());
            entity.setRuleName(dto.ruleName());
            entity.setSeverity(dto.severity());
            entity.setOutcomeClassification(dto.outcomeClassification());
            entity.setActor(dto.actor());
            entity.setServicePath(dto.servicePath());
            entity.setEventIdsJson(CanonicalJsonUtil.toCanonicalJson(dto.eventIds()));
            entity.setCorrelationId(dto.correlationId());
            entity.setSessionId(dto.sessionId());
            entity.setSourceEventTimeUtc(dto.timestamp());
            entity.setDetectedAt(detectedAt);
            entity.setDetectionLatencyMs(elapsedMs);
            entity.setExplanation(dto.explanation());
            entity.setDatasetSource(PRACTICE_SOURCE);
            alertRepository.save(entity);
        }

        String actor = currentActorOrSystem();
        auditLogService.appendEvent(
                actor,
                "DETECTION_EVALUATED",
                PRACTICE_SOURCE,
                "Evaluated " + events.size() + " events using deterministic rules (labels excluded from detector); "
                        + "exactMatches=" + metrics.exactLabelMatches() + "/" + metrics.sampleSize()
        );

        DetectionEvaluationResponse response = new DetectionEvaluationResponse(
                PRACTICE_SOURCE,
                events.size(),
                false,
                output.classifiedEvents(),
                output.alerts(),
                metrics,
                PRACTICE_LIMITATION
        );
        this.lastPracticeRun = response;
        return response;
    }

    public DetectionEvaluationResponse getLatestPracticeEvaluation() {
        if (lastPracticeRun == null) {
            return evaluatePracticeDataset();
        }
        return lastPracticeRun;
    }

    public List<AlertDto> listAllAlerts() {
        return alertRepository.findAllByOrderByDetectedAtDesc().stream()
                .map(this::toDto)
                .toList();
    }

    private AlertDto toDto(SecurityAlertEntity e) {
        List<String> eventIds;
        try {
            eventIds = objectMapper.readValue(e.getEventIdsJson(), new TypeReference<>() {});
        } catch (Exception ex) {
            eventIds = List.of();
        }
        return new AlertDto(
                e.getAlertUid(),
                e.getRuleName(),
                e.getSeverity(),
                e.getOutcomeClassification(),
                e.getActor(),
                e.getServicePath(),
                eventIds,
                e.getCorrelationId(),
                e.getSessionId(),
                e.getSourceEventTimeUtc() != null ? e.getSourceEventTimeUtc() : e.getDetectedAt(),
                e.getExplanation(),
                e.getDatasetSource()
        );
    }

    private String currentActorOrSystem() {
        try {
            return SecurityUtils.currentUsername();
        } catch (Exception e) {
            return "system";
        }
    }
}
