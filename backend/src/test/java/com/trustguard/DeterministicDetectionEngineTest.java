package com.trustguard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.detection.DeterministicDetectionEngine;
import com.trustguard.detection.PracticeDatasetLoader;
import com.trustguard.detection.PracticeEvaluator;
import com.trustguard.detection.PracticeModels;
import com.trustguard.detection.PracticeModels.ApprovalChange;
import com.trustguard.detection.PracticeModels.ExpectedLabel;
import com.trustguard.detection.PracticeModels.PracticeEvent;
import com.trustguard.dto.DetectionEvaluationResponse.AlertDto;
import com.trustguard.dto.DetectionEvaluationResponse.ClassifiedEventDto;
import com.trustguard.dto.DetectionEvaluationResponse.EvaluationMetricsDto;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class DeterministicDetectionEngineTest {

    static class TrackingDatasetLoader extends PracticeDatasetLoader {
        final AtomicBoolean labelsAccessed = new AtomicBoolean(false);

        TrackingDatasetLoader(ObjectMapper objectMapper) {
            super(objectMapper);
        }

        @Override
        public List<ExpectedLabel> loadLabelsOnlyForPostEvaluation() {
            labelsAccessed.set(true);
            return super.loadLabelsOnlyForPostEvaluation();
        }
    }

    @Test
    void evaluatesAll22PracticeEventsWithoutUsingLabelsInDetection() {
        TrackingDatasetLoader loader = new TrackingDatasetLoader(new ObjectMapper());

        List<PracticeEvent> events = loader.loadEvents();
        List<ApprovalChange> approvals = loader.loadApprovals();
        assertEquals(22, events.size());

        // Structural isolation: detector has zero dependency on PracticeDatasetLoader, PracticeEvaluator, or ExpectedLabel
        for (Field f : DeterministicDetectionEngine.class.getDeclaredFields()) {
            assertNotEquals(PracticeDatasetLoader.class, f.getType());
            assertNotEquals(PracticeEvaluator.class, f.getType());
        }
        for (Method m : DeterministicDetectionEngine.class.getDeclaredMethods()) {
            for (Parameter p : m.getParameters()) {
                assertNotEquals(PracticeDatasetLoader.class, p.getType());
                assertNotEquals(ExpectedLabel.class, p.getType());
            }
        }

        DeterministicDetectionEngine engine = new DeterministicDetectionEngine();
        DeterministicDetectionEngine.EngineOutput output = engine.evaluatePracticeEvents(events, approvals);

        // Ensure detector never touched ground-truth labels
        assertFalse(loader.labelsAccessed.get(), "Detector must never load ground-truth labels");

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
        assertTrue(loader.labelsAccessed.get());
        assertEquals(22, metrics.sampleSize());
        assertEquals(22, metrics.exactLabelMatches());
        assertEquals(1.0, metrics.precision());
        assertEquals(1.0, metrics.recall());
        assertEquals(1.0, metrics.f1Score());
        assertEquals(0.0, metrics.falseAlertsPer1000Benign());
    }

    @Test
    void detectsEvasionVectorsLateralRotationCrossSessionEscalationClockSkewAndLateRevocationProbes() {
        List<ApprovalChange> approvals = List.of(
                new ApprovalChange(
                        "change-100",
                        "user-admin",
                        "user-alex",
                        "grant_role",
                        "report-reader",
                        List.of("reports", "reports-node-a"),
                        Instant.parse("2026-01-15T09:01:00Z"),
                        Instant.parse("2026-01-15T09:07:00Z"),
                        null
                ),
                new ApprovalChange(
                        "change-101",
                        "user-admin",
                        "user-alex",
                        "revoke_role",
                        "report-reader",
                        List.of(),
                        null,
                        null,
                        Instant.parse("2026-01-15T09:07:00Z")
                )
        );

        List<PracticeEvent> adversarial = List.of(
                // 1. Multi-hop denied lateral movement with rotating session_id and correlation_id within 5 min window
                new PracticeEvent("adv-lat-1", Instant.parse("2026-01-15T09:04:00Z"), Instant.parse("2026-01-15T09:04:00.1Z"),
                        0, "svc-probe", "reports", "billing", "read", "service-reader", "service-reader", "deny", "", "sess-a", "corr-a"),
                new PracticeEvent("adv-lat-2", Instant.parse("2026-01-15T09:04:08Z"), Instant.parse("2026-01-15T09:04:08.1Z"),
                        0, "svc-probe", "billing", "archive", "read", "service-reader", "service-reader", "deny", "", "sess-b", "corr-b"),

                // 2. Unexpected ALLOWED service edge on non-normal pair (isolated single allow)
                new PracticeEvent("adv-allow-1", Instant.parse("2026-01-15T09:05:00Z"), Instant.parse("2026-01-15T09:05:00.1Z"),
                        0, "user-eve", "reports", "billing", "read", "viewer", "viewer", "allow", "", "sess-e1", "corr-e1"),

                // 3. Cross-session privilege escalation: unapproved role_change in sess-b1 followed by allow in sess-b2
                new PracticeEvent("adv-rc-1", Instant.parse("2026-01-15T09:06:00Z"), Instant.parse("2026-01-15T09:06:00.1Z"),
                        0, "user-blair", "admin-console", "identity", "role_change", "viewer", "operator", "success", "", "sess-b1", "corr-r1"),
                new PracticeEvent("adv-rc-2", Instant.parse("2026-01-15T09:06:30Z"), Instant.parse("2026-01-15T09:06:30.1Z"),
                        0, "user-blair", "portal", "catalog", "read", "operator", "operator", "allow", "", "sess-b2", "corr-r2"),

                // 4. Excessive clock offset attempting to drag 09:25 event back into expired 09:01..09:07 window
                new PracticeEvent("adv-clk-1", Instant.parse("2026-01-15T09:25:00Z"), Instant.parse("2026-01-15T09:25:00.2Z"),
                        1_200_000L, "user-alex", "portal", "reports", "read", "report-reader", "report-reader", "allow", "change-100", "sess-c1", "corr-c1"),

                // 5. Post-revocation denial 10 minutes AFTER revocation (outside 60s transition window, >5 min away from 09:25) -> isolated_denial!
                new PracticeEvent("adv-rev-late", Instant.parse("2026-01-15T09:17:00Z"), Instant.parse("2026-01-15T09:17:00.1Z"),
                        0, "user-alex", "portal", "reports-node-a", "read", "viewer", "viewer", "deny", "", "sess-alex", "corr-l1")
        );

        DeterministicDetectionEngine engine = new DeterministicDetectionEngine();
        DeterministicDetectionEngine.EngineOutput output = engine.evaluatePracticeEvents(adversarial, approvals);
        Map<String, ClassifiedEventDto> byId = output.classifiedEvents().stream()
                .collect(Collectors.toMap(ClassifiedEventDto::eventId, Function.identity()));

        // Lateral movement across rotating correlation/session ids caught
        assertEquals("lateral_movement_candidate", byId.get("adv-lat-1").predictedLabel());
        assertEquals("lateral_movement_candidate", byId.get("adv-lat-2").predictedLabel());
        assertTrue(output.alerts().stream().anyMatch(a ->
                "lateral_movement_candidate".equals(a.ruleName())
                        && a.eventIds().equals(List.of("adv-lat-1", "adv-lat-2"))));

        // Unexpected allow edge flagged
        assertEquals("unexpected_service_access", byId.get("adv-allow-1").predictedLabel());
        assertTrue(output.alerts().stream().anyMatch(a ->
                "unexpected_allowed_service_edge".equals(a.ruleName()) && "user-eve".equals(a.actor())));

        // Cross-session escalation flagged
        assertEquals("unexpected_role_change", byId.get("adv-rc-1").predictedLabel());
        assertEquals("review_after_role_change", byId.get("adv-rc-2").predictedLabel());
        assertTrue(output.alerts().stream().anyMatch(a ->
                "suspicious_privilege_escalation".equals(a.ruleName())
                        && a.eventIds().equals(List.of("adv-rc-1", "adv-rc-2"))));

        // Excessive clock offset rejected/flagged (never treated as routine_clock_offset)
        assertEquals("suspicious_clock_offset", byId.get("adv-clk-1").predictedLabel());
        assertTrue(output.alerts().stream().anyMatch(a ->
                "implausible_clock_offset".equals(a.ruleName()) && a.eventIds().contains("adv-clk-1")));

        // Late post-revocation denial NOT suppressed as routine_denial
        assertEquals("isolated_denial", byId.get("adv-rev-late").predictedLabel());
        assertTrue(output.alerts().stream().anyMatch(a ->
                "isolated_denied_request".equals(a.ruleName()) && a.eventIds().contains("adv-rev-late")));
    }
}
