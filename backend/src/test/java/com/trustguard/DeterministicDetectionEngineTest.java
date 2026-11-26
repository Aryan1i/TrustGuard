package com.trustguard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.detection.DeterministicDetectionEngine;
import com.trustguard.detection.PracticeDatasetLoader;
import com.trustguard.detection.PracticeEvaluator;
import com.trustguard.detection.PracticeModels;
import com.trustguard.dto.DetectionEvaluationResponse.AlertDto;
import com.trustguard.dto.DetectionEvaluationResponse.ClassifiedEventDto;
import com.trustguard.dto.DetectionEvaluationResponse.EvaluationMetricsDto;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class DeterministicDetectionEngineTest {

    @Test
    void evaluatesAll22PracticeEventsWithoutUsingLabelsInDetection() {
        PracticeDatasetLoader loader = new PracticeDatasetLoader(new ObjectMapper());
        PracticeDatasetLoader spyLoader = Mockito.spy(loader);

        List<PracticeModels.PracticeEvent> events = spyLoader.loadEvents();
        List<PracticeModels.ApprovalChange> approvals = spyLoader.loadApprovals();
        assertEquals(22, events.size());

        DeterministicDetectionEngine engine = new DeterministicDetectionEngine();
        DeterministicDetectionEngine.EngineOutput output = engine.evaluatePracticeEvents(events, approvals);

        // Ensure detector never touches ground-truth labels
        Mockito.verify(spyLoader, Mockito.never()).loadLabelsOnlyForPostEvaluation();

        Map<String, ClassifiedEventDto> byId = output.classifiedEvents().stream()
                .collect(Collectors.toMap(ClassifiedEventDto::eventId, Function.identity()));

        // Approved role change
        assertEquals("approved_change", byId.get("evt-003").predictedLabel());
        assertEquals("approved_change", byId.get("evt-004").predictedLabel());
        assertEquals("routine", byId.get("evt-005").predictedLabel());

        // Unexpected role change & follow-up read
        assertEquals("unexpected_role_change", byId.get("evt-008").predictedLabel());
        assertEquals("review_after_role_change", byId.get("evt-009").predictedLabel());

        // Candidate lateral movement (denied attempts, NOT successful compromise)
        assertEquals("lateral_movement_candidate", byId.get("evt-010").predictedLabel());
        assertEquals("lateral_movement_candidate", byId.get("evt-011").predictedLabel());
        assertEquals("lateral_movement_candidate", byId.get("evt-012").predictedLabel());
        AlertDto lateralAlert = output.alerts().stream()
                .filter(a -> "lateral_movement_candidate".equals(a.ruleName()))
                .findFirst().orElseThrow();
        assertEquals("DENIED_ATTEMPT", lateralAlert.outcomeClassification());
        assertEquals(List.of("evt-010", "evt-011", "evt-012"), lateralAlert.eventIds());

        // Out-of-order delivery preserved & explained
        assertTrue(byId.get("evt-013").outOfOrderArrival());
        assertEquals("routine_delayed_delivery", byId.get("evt-013").predictedLabel());
        assertEquals("routine", byId.get("evt-014").predictedLabel());

        // Clock offset correction (+2000ms subtracted -> 09:06:01Z, 200ms delay)
        assertEquals(Instant.parse("2026-01-15T09:06:01.000Z"), byId.get("evt-015").correctedEventTimeUtc());
        assertEquals(200L, byId.get("evt-015").deliveryDelayMs());
        assertEquals("routine_clock_offset", byId.get("evt-015").predictedLabel());

        // Revocation enforcement & remaining catalog scope
        assertEquals("approved_change", byId.get("evt-016").predictedLabel());
        assertEquals("routine_denial", byId.get("evt-017").predictedLabel());
        assertEquals("routine_denial", byId.get("evt-018").predictedLabel());
        assertEquals("isolated_denial", byId.get("evt-020").predictedLabel());
        assertEquals("routine", byId.get("evt-021").predictedLabel());

        // Post-detection evaluation against labels.csv
        PracticeEvaluator evaluator = new PracticeEvaluator();
        EvaluationMetricsDto metrics = evaluator.evaluateAgainstLabels(
                output.classifiedEvents(),
                loader.loadLabelsOnlyForPostEvaluation()
        );
        assertEquals(22, metrics.sampleSize());
        assertEquals(22, metrics.exactLabelMatches());
        assertEquals(1.0, metrics.precision());
        assertEquals(1.0, metrics.recall());
        assertEquals(1.0, metrics.f1Score());
        assertEquals(0.0, metrics.falseAlertsPer1000Benign());
    }
}
