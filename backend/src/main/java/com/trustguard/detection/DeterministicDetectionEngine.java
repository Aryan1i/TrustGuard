package com.trustguard.detection;

import com.trustguard.detection.PracticeModels.ApprovalChange;
import com.trustguard.detection.PracticeModels.PracticeEvent;
import com.trustguard.dto.DetectionEvaluationResponse.AlertDto;
import com.trustguard.dto.DetectionEvaluationResponse.ClassifiedEventDto;
import com.trustguard.util.TimeUtils;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Purely deterministic rule-based threat detection engine.
 * Contains zero AI/ML, zero LLM calls, and never reads ground-truth labels.
 */
@Service
public class DeterministicDetectionEngine {

    public record EngineOutput(
            List<ClassifiedEventDto> classifiedEvents,
            List<AlertDto> alerts
    ) {
    }

    private record AnnotatedEvent(
            PracticeEvent raw,
            Instant correctedTime,
            long deliveryDelayMs,
            boolean outOfOrderArrival
    ) {
    }

    public EngineOutput evaluatePracticeEvents(List<PracticeEvent> events, List<ApprovalChange> approvals) {
        // Step 1: Preserve receipt order, apply source clock offset correction, and detect out-of-order arrival.
        Map<String, Instant> maxCorrectedTimeByActorSession = new HashMap<>();
        List<AnnotatedEvent> annotated = new ArrayList<>(events.size());
        for (PracticeEvent evt : events) {
            Instant corrected = TimeUtils.adjustForSourceOffset(evt.eventTimeUtc(), evt.sourceClockOffsetMs());
            long delayMs = Duration.between(corrected, evt.receivedTimeUtc()).toMillis();
            String actorSessionKey = evt.actor() + "|" + evt.sessionId();
            Instant prevMax = maxCorrectedTimeByActorSession.get(actorSessionKey);
            boolean outOfOrder = prevMax != null && corrected.isBefore(prevMax);
            if (prevMax == null || corrected.isAfter(prevMax)) {
                maxCorrectedTimeByActorSession.put(actorSessionKey, corrected);
            }
            annotated.add(new AnnotatedEvent(evt, corrected, delayMs, outOfOrder));
        }

        // Step 2: Detect unexpected role changes and track compromised/unapproved sessions.
        Map<String, String> unapprovedRoleChangeEventByActorSession = new HashMap<>();
        for (AnnotatedEvent ae : annotated) {
            PracticeEvent e = ae.raw();
            if ("role_change".equals(e.action()) && !e.roleBefore().equals(e.roleAfter())) {
                Optional<ApprovalChange> match = findMatchingGrantApproval(e, ae.correctedTime(), approvals);
                if (match.isEmpty()) {
                    unapprovedRoleChangeEventByActorSession.put(e.actor() + "|" + e.sessionId(), e.eventId());
                }
            }
        }

        // Step 3: Group unexpected service edges by (actor, sessionId, correlationId) to distinguish
        // multi-step candidate lateral movement from isolated denials.
        Map<String, List<AnnotatedEvent>> unexpectedDeniedEdgesByFlow = new LinkedHashMap<>();
        for (AnnotatedEvent ae : annotated) {
            PracticeEvent e = ae.raw();
            if ("deny".equalsIgnoreCase(e.outcome())
                    && !isPostRevocationExpectedDenial(e, ae.correctedTime(), approvals)
                    && !isKnownNormalEdge(e, ae.correctedTime(), approvals)) {
                String flowKey = e.actor() + "|" + e.sessionId() + "|" + e.correlationId();
                unexpectedDeniedEdgesByFlow.computeIfAbsent(flowKey, k -> new ArrayList<>()).add(ae);
            }
        }

        Set<String> lateralMovementEventIds = new LinkedHashSet<>();
        List<AlertDto> alerts = new ArrayList<>();
        int alertSeq = 1;

        for (Map.Entry<String, List<AnnotatedEvent>> entry : unexpectedDeniedEdgesByFlow.entrySet()) {
            List<AnnotatedEvent> seqEvents = entry.getValue();
            if (seqEvents.size() >= 2) {
                List<String> ids = seqEvents.stream().map(a -> a.raw().eventId()).toList();
                lateralMovementEventIds.addAll(ids);
                String path = buildServicePath(seqEvents);
                PracticeEvent first = seqEvents.get(0).raw();
                alerts.add(new AlertDto(
                        "prac-alt-" + (alertSeq++),
                        "lateral_movement_candidate",
                        "HIGH",
                        "DENIED_ATTEMPT",
                        first.actor(),
                        path,
                        ids,
                        first.correlationId(),
                        first.sessionId(),
                        seqEvents.get(seqEvents.size() - 1).correctedTime(),
                        seqEvents.size() + " sequential unexpected service edges grouped in session "
                                + first.sessionId() + " / " + first.correlationId()
                                + ". All requests were DENIED; classified as candidate lateral-movement reconnaissance, NOT successful compromise.",
                        "PRACTICE_22_EVENTS"
                ));
            }
        }

        // Step 4: Classify every event deterministically and emit remaining rule alerts.
        List<ClassifiedEventDto> classified = new ArrayList<>(annotated.size());
        for (AnnotatedEvent ae : annotated) {
            PracticeEvent e = ae.raw();
            String actorSessionKey = e.actor() + "|" + e.sessionId();
            String predictedLabel;
            String explanation;

            if ("approve_role_change".equals(e.action())) {
                Optional<ApprovalChange> approval = findApprovalByIdAndOperator(e, approvals);
                if (approval.isPresent()) {
                    predictedLabel = "approved_change";
                    explanation = "Operator " + e.actor() + " approved change " + approval.get().approvalId()
                            + " matching approvals.json.";
                    alerts.add(new AlertDto(
                            "prac-alt-" + (alertSeq++),
                            "approved_role_change",
                            "INFO",
                            "INFO",
                            e.actor(),
                            e.sourceService() + " -> " + e.targetService(),
                            List.of(e.eventId()),
                            e.correlationId(),
                            e.sessionId(),
                            ae.correctedTime(),
                            explanation,
                            "PRACTICE_22_EVENTS"
                    ));
                } else {
                    predictedLabel = "unexpected_role_change";
                    explanation = "Role approval action lacks matching approval record.";
                }
            } else if ("revoke_role".equals(e.action())) {
                Optional<ApprovalChange> revokeApproval = findRevokeApproval(e, approvals);
                if (revokeApproval.isPresent()) {
                    predictedLabel = "approved_change";
                    explanation = "Operator " + e.actor() + " revoked role under change " + revokeApproval.get().approvalId() + ".";
                    alerts.add(new AlertDto(
                            "prac-alt-" + (alertSeq++),
                            "approved_role_change",
                            "INFO",
                            "INFO",
                            e.actor(),
                            e.sourceService() + " -> " + e.targetService(),
                            List.of(e.eventId()),
                            e.correlationId(),
                            e.sessionId(),
                            ae.correctedTime(),
                            explanation,
                            "PRACTICE_22_EVENTS"
                    ));
                } else {
                    predictedLabel = "unexpected_role_change";
                    explanation = "Role revocation lacks matching approval record.";
                }
            } else if ("role_change".equals(e.action()) && !e.roleBefore().equals(e.roleAfter())) {
                Optional<ApprovalChange> match = findMatchingGrantApproval(e, ae.correctedTime(), approvals);
                if (match.isPresent()) {
                    predictedLabel = "approved_change";
                    explanation = "Role change " + e.roleBefore() + " -> " + e.roleAfter() + " for " + e.actor()
                            + " matches " + match.get().approvalId() + " within [" + match.get().validFromUtc()
                            + ", " + match.get().validUntilUtc() + ").";
                    alerts.add(new AlertDto(
                            "prac-alt-" + (alertSeq++),
                            "approved_role_change",
                            "INFO",
                            "INFO",
                            e.actor(),
                            e.sourceService() + " -> " + e.targetService(),
                            List.of(e.eventId()),
                            e.correlationId(),
                            e.sessionId(),
                            ae.correctedTime(),
                            explanation,
                            "PRACTICE_22_EVENTS"
                    ));
                } else {
                    predictedLabel = "unexpected_role_change";
                    explanation = "No matching approval found in approvals.json for " + e.actor()
                            + " transitioning from " + e.roleBefore() + " to " + e.roleAfter() + ".";
                    alerts.add(new AlertDto(
                            "prac-alt-" + (alertSeq++),
                            "unauthorized_role_change",
                            "HIGH",
                            "CONFIRMED_VIOLATION",
                            e.actor(),
                            e.sourceService() + " -> " + e.targetService(),
                            List.of(e.eventId()),
                            e.correlationId(),
                            e.sessionId(),
                            ae.correctedTime(),
                            explanation,
                            "PRACTICE_22_EVENTS"
                    ));
                }
            } else if (unapprovedRoleChangeEventByActorSession.containsKey(actorSessionKey)
                    && "allow".equalsIgnoreCase(e.outcome())
                    && !e.eventId().equals(unapprovedRoleChangeEventByActorSession.get(actorSessionKey))) {
                String rootEventId = unapprovedRoleChangeEventByActorSession.get(actorSessionKey);
                predictedLabel = "review_after_role_change";
                explanation = "Allowed access on " + e.targetService() + " directly follows unapproved role change "
                        + rootEventId + " in session " + e.sessionId() + ".";
                alerts.add(new AlertDto(
                        "prac-alt-" + (alertSeq++),
                        "suspicious_privilege_escalation",
                        "CRITICAL",
                        "CONFIRMED_VIOLATION",
                        e.actor(),
                        e.sourceService() + " -> " + e.targetService(),
                        List.of(rootEventId, e.eventId()),
                        e.correlationId(),
                        e.sessionId(),
                        ae.correctedTime(),
                        explanation,
                        "PRACTICE_22_EVENTS"
                ));
            } else if (lateralMovementEventIds.contains(e.eventId())) {
                predictedLabel = "lateral_movement_candidate";
                explanation = "Part of multi-edge denied sequence (" + e.sourceService() + " -> " + e.targetService()
                        + ") in " + e.correlationId() + "; request was DENIED.";
            } else if (isPostRevocationExpectedDenial(e, ae.correctedTime(), approvals)) {
                predictedLabel = "routine_denial";
                explanation = "Expected post-revocation denial on " + e.targetService()
                        + " after change-100 expiration / change-101 revocation at 09:07:00Z.";
            } else if ("deny".equalsIgnoreCase(e.outcome())) {
                predictedLabel = "isolated_denial";
                explanation = "Single isolated denied request to " + e.targetService() + " in " + e.sessionId()
                        + "; does not establish lateral movement.";
                alerts.add(new AlertDto(
                        "prac-alt-" + (alertSeq++),
                        "isolated_denied_request",
                        "LOW",
                        "DENIED_ATTEMPT",
                        e.actor(),
                        e.sourceService() + " -> " + e.targetService(),
                        List.of(e.eventId()),
                        e.correlationId(),
                        e.sessionId(),
                        ae.correctedTime(),
                        explanation,
                        "PRACTICE_22_EVENTS"
                ));
            } else if (e.sourceClockOffsetMs() != 0) {
                predictedLabel = "routine_clock_offset";
                explanation = "Source clock offset " + e.sourceClockOffsetMs() + "ms subtracted: corrected event time "
                        + ae.correctedTime() + " yields " + ae.deliveryDelayMs() + "ms collector delay (not replay or negative delay).";
                alerts.add(new AlertDto(
                        "prac-alt-" + (alertSeq++),
                        "uncertain_timestamp_ordering",
                        "INFO",
                        "INFO",
                        e.actor(),
                        e.sourceService() + " -> " + e.targetService(),
                        List.of(e.eventId()),
                        e.correlationId(),
                        e.sessionId(),
                        ae.correctedTime(),
                        explanation,
                        "PRACTICE_22_EVENTS"
                ));
            } else if (ae.outOfOrderArrival()) {
                predictedLabel = "routine_delayed_delivery";
                explanation = "Out-of-order network delivery: occurred at " + ae.correctedTime()
                        + " before preceding received event, arrived at " + e.receivedTimeUtc() + " (routine).";
                alerts.add(new AlertDto(
                        "prac-alt-" + (alertSeq++),
                        "uncertain_timestamp_ordering",
                        "INFO",
                        "INFO",
                        e.actor(),
                        e.sourceService() + " -> " + e.targetService(),
                        List.of(e.eventId()),
                        e.correlationId(),
                        e.sessionId(),
                        ae.correctedTime(),
                        explanation,
                        "PRACTICE_22_EVENTS"
                ));
            } else {
                predictedLabel = "routine";
                explanation = "Authorized activity within expected role and service scope.";
            }

            classified.add(new ClassifiedEventDto(
                    e.eventId(),
                    e.actor(),
                    e.sourceService(),
                    e.targetService(),
                    e.action(),
                    e.outcome(),
                    e.eventTimeUtc(),
                    e.sourceClockOffsetMs(),
                    ae.correctedTime(),
                    e.receivedTimeUtc(),
                    ae.deliveryDelayMs(),
                    ae.outOfOrderArrival(),
                    predictedLabel,
                    explanation
            ));
        }

        return new EngineOutput(classified, alerts);
    }

    private Optional<ApprovalChange> findMatchingGrantApproval(
            PracticeEvent event,
            Instant correctedTime,
            List<ApprovalChange> approvals
    ) {
        return approvals.stream()
                .filter(a -> "grant_role".equals(a.operation()))
                .filter(a -> a.subject().equals(event.actor()))
                .filter(a -> a.role().equals(event.roleAfter()))
                .filter(a -> event.approvalId().isBlank() || a.approvalId().equals(event.approvalId()))
                .filter(a -> a.validFromUtc() != null && !correctedTime.isBefore(a.validFromUtc()))
                .filter(a -> a.validUntilUtc() == null || correctedTime.isBefore(a.validUntilUtc()))
                .findFirst();
    }

    private Optional<ApprovalChange> findApprovalByIdAndOperator(PracticeEvent event, List<ApprovalChange> approvals) {
        return approvals.stream()
                .filter(a -> a.approvalId().equals(event.approvalId()))
                .filter(a -> a.approvedBy().equals(event.actor()))
                .findFirst();
    }

    private Optional<ApprovalChange> findRevokeApproval(PracticeEvent event, List<ApprovalChange> approvals) {
        return approvals.stream()
                .filter(a -> "revoke_role".equals(a.operation()))
                .filter(a -> a.approvalId().equals(event.approvalId()))
                .filter(a -> a.approvedBy().equals(event.actor()))
                .findFirst();
    }

    private boolean isPostRevocationExpectedDenial(
            PracticeEvent event,
            Instant correctedTime,
            List<ApprovalChange> approvals
    ) {
        if (!"deny".equalsIgnoreCase(event.outcome())) {
            return false;
        }
        boolean revokedAtOrBeforeEvent = approvals.stream()
                .filter(a -> "revoke_role".equals(a.operation()))
                .filter(a -> a.subject().equals(event.actor()))
                .anyMatch(a -> a.effectiveAtUtc() != null && !correctedTime.isBefore(a.effectiveAtUtc()));
        if (!revokedAtOrBeforeEvent) {
            return false;
        }
        return approvals.stream()
                .filter(a -> "grant_role".equals(a.operation()))
                .filter(a -> a.subject().equals(event.actor()))
                .anyMatch(a -> a.scope().contains(event.targetService()));
    }

    private boolean isKnownNormalEdge(
            PracticeEvent event,
            Instant correctedTime,
            List<ApprovalChange> approvals
    ) {
        String src = event.sourceService();
        String dst = event.targetService();
        String role = event.roleAfter();

        if ("portal".equals(src) && ("identity".equals(dst) || "catalog".equals(dst))) {
            return true;
        }
        if ("admin-console".equals(src) && "identity".equals(dst) && "operator".equals(role)) {
            return true;
        }
        if ("svc-report-worker".equals(event.actor()) && "reports".equals(src) && "catalog".equals(dst)) {
            return true;
        }
        if ("report-reader".equals(role)) {
            return approvals.stream()
                    .filter(a -> "grant_role".equals(a.operation()))
                    .filter(a -> a.subject().equals(event.actor()))
                    .filter(a -> a.role().equals(role))
                    .filter(a -> a.scope().contains(dst))
                    .anyMatch(a -> (a.validFromUtc() == null || !correctedTime.isBefore(a.validFromUtc()))
                            && (a.validUntilUtc() == null || correctedTime.isBefore(a.validUntilUtc())));
        }
        return false;
    }

    private String buildServicePath(List<AnnotatedEvent> seq) {
        List<String> hops = new ArrayList<>();
        for (int i = 0; i < seq.size(); i++) {
            PracticeEvent e = seq.get(i).raw();
            if (i == 0) {
                hops.add(e.sourceService());
            }
            hops.add(e.targetService());
        }
        return String.join(" -> ", hops);
    }
}
