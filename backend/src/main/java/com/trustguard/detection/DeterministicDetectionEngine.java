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
import java.util.Comparator;
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

    public static final long MAX_PLAUSIBLE_CLOCK_OFFSET_MS = 30_000L;
    public static final long MAX_PLAUSIBLE_OFFSET_DELAY_MS = 30_000L;
    public static final long LATERAL_MOVEMENT_WINDOW_MS = 300_000L;
    public static final long SLOW_LATERAL_WINDOW_MS = 86_400_000L;
    public static final long POST_REVOCATION_TRANSITION_WINDOW_SECONDS = 60L;

    public record EngineOutput(
            List<ClassifiedEventDto> classifiedEvents,
            List<AlertDto> alerts
    ) {
    }

    private record AnnotatedEvent(
            int orderIndex,
            PracticeEvent raw,
            Instant correctedTime,
            Instant policyTime,
            long deliveryDelayMs,
            boolean outOfOrderArrival,
            boolean implausibleClockOffset
    ) {
    }

    private record RoleEscalation(
            int orderIndex,
            Instant policyTime,
            String eventId,
            String sessionId
    ) {
    }

    private record RoleRevocation(
            int orderIndex,
            Instant policyTime
    ) {
    }

    public EngineOutput evaluatePracticeEvents(List<PracticeEvent> events, List<ApprovalChange> approvals) {
        // Step 1: Preserve receipt order, validate clock-offset plausibility, and detect out-of-order arrival.
        Map<String, Instant> maxTimeByActorSession = new HashMap<>();
        List<AnnotatedEvent> annotated = new ArrayList<>(events.size());
        for (int idx = 0; idx < events.size(); idx++) {
            PracticeEvent evt = events.get(idx);
            Instant corrected = TimeUtils.adjustForSourceOffset(evt.eventTimeUtc(), evt.sourceClockOffsetMs());
            long delayMs = Duration.between(corrected, evt.receivedTimeUtc()).toMillis();

            boolean implausibleOffset = isImplausibleClockOffset(evt, corrected, delayMs, approvals);
            Instant policyTime = implausibleOffset ? evt.receivedTimeUtc() : corrected;

            String actorSessionKey = evt.actor() + "|" + evt.sessionId();
            Instant prevMax = maxTimeByActorSession.get(actorSessionKey);
            boolean outOfOrder = prevMax != null && policyTime.isBefore(prevMax);
            if (!implausibleOffset && (prevMax == null || policyTime.isAfter(prevMax))) {
                maxTimeByActorSession.put(actorSessionKey, policyTime);
            }
            annotated.add(new AnnotatedEvent(idx, evt, corrected, policyTime, delayMs, outOfOrder, implausibleOffset));
        }

        // Step 2: Detect unapproved role changes and approved role revocations per actor.
        Map<String, List<RoleEscalation>> unapprovedRoleChangesByActor = new HashMap<>();
        Map<String, List<RoleRevocation>> approvedRevocationsBySubject = new HashMap<>();
        for (AnnotatedEvent ae : annotated) {
            PracticeEvent e = ae.raw();
            if ("role_change".equals(e.action()) && !e.roleBefore().equals(e.roleAfter())) {
                Optional<ApprovalChange> match = findMatchingGrantApproval(e, ae.policyTime(), approvals);
                if (match.isEmpty()) {
                    unapprovedRoleChangesByActor
                            .computeIfAbsent(e.actor(), k -> new ArrayList<>())
                            .add(new RoleEscalation(ae.orderIndex(), ae.policyTime(), e.eventId(), e.sessionId()));
                }
            } else if ("revoke_role".equals(e.action())) {
                findRevokeApproval(e, approvals).ifPresent(rev ->
                        approvedRevocationsBySubject
                                .computeIfAbsent(rev.subject(), k -> new ArrayList<>())
                                .add(new RoleRevocation(ae.orderIndex(), ae.policyTime()))
                );
            }
        }

        // Step 3: Detect multi-hop unexpected service edges per actor within a bounded time window,
        // plus slow-and-low probes across >= 3 distinct target services within a 24h horizon.
        Map<String, List<AnnotatedEvent>> unexpectedEdgesByActor = new LinkedHashMap<>();
        for (AnnotatedEvent ae : annotated) {
            PracticeEvent e = ae.raw();
            boolean isDeny = "deny".equalsIgnoreCase(e.outcome());
            boolean isAllow = "allow".equalsIgnoreCase(e.outcome());
            if (!isDeny && !isAllow) {
                continue;
            }
            if (isAllow && findPriorRoleEscalation(e.actor(), ae, unapprovedRoleChangesByActor, approvedRevocationsBySubject).isPresent()) {
                // Handled directly as post-role-change escalation follow-up
                continue;
            }
            if (!isPostRevocationExpectedDenial(e, ae.policyTime(), approvals)
                    && !isKnownNormalEdge(e, ae.policyTime(), approvals)) {
                unexpectedEdgesByActor.computeIfAbsent(e.actor(), k -> new ArrayList<>()).add(ae);
            }
        }

        Set<String> lateralMovementEventIds = new LinkedHashSet<>();
        List<AlertDto> alerts = new ArrayList<>();
        int alertSeq = 1;

        for (Map.Entry<String, List<AnnotatedEvent>> entry : unexpectedEdgesByActor.entrySet()) {
            List<AnnotatedEvent> sorted = entry.getValue().stream()
                    .sorted(Comparator.comparing(AnnotatedEvent::policyTime).thenComparingInt(AnnotatedEvent::orderIndex))
                    .toList();

            List<List<AnnotatedEvent>> clusters = clusterByBoundedWindow(sorted, LATERAL_MOVEMENT_WINDOW_MS);
            for (List<AnnotatedEvent> cluster : clusters) {
                if (cluster.size() >= 2) {
                    alerts.add(buildLateralAlert(cluster, alertSeq++, false, lateralMovementEventIds));
                }
            }

            List<AnnotatedEvent> remaining = sorted.stream()
                    .filter(ae -> !lateralMovementEventIds.contains(ae.raw().eventId()))
                    .toList();
            List<List<AnnotatedEvent>> slowClusters = clusterByBoundedWindow(remaining, SLOW_LATERAL_WINDOW_MS);
            for (List<AnnotatedEvent> slowCluster : slowClusters) {
                long distinctTargets = slowCluster.stream()
                        .map(ae -> ae.raw().targetService())
                        .filter(s -> s != null && !s.isBlank())
                        .distinct()
                        .count();
                if (distinctTargets >= 3) {
                    alerts.add(buildLateralAlert(slowCluster, alertSeq++, true, lateralMovementEventIds));
                }
            }
        }

        // Step 4: Classify every event deterministically and emit remaining rule alerts.
        List<ClassifiedEventDto> classified = new ArrayList<>(annotated.size());
        for (AnnotatedEvent ae : annotated) {
            PracticeEvent e = ae.raw();
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
                Optional<ApprovalChange> match = findMatchingGrantApproval(e, ae.policyTime(), approvals);
                if (match.isPresent() && !ae.implausibleClockOffset()) {
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
                    explanation = ae.implausibleClockOffset()
                            ? "Role change clock offset (" + e.sourceClockOffsetMs() + "ms) rejected; no valid active approval at collector receipt time " + ae.policyTime() + "."
                            : "No matching approval found in approvals.json for " + e.actor()
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
                            ae.policyTime(),
                            explanation,
                            "PRACTICE_22_EVENTS"
                    ));
                    if (ae.implausibleClockOffset()) {
                        alerts.add(new AlertDto(
                                "prac-alt-" + (alertSeq++),
                                "implausible_clock_offset",
                                "HIGH",
                                "CONFIRMED_VIOLATION",
                                e.actor(),
                                e.sourceService() + " -> " + e.targetService(),
                                List.of(e.eventId()),
                                e.correlationId(),
                                e.sessionId(),
                                ae.policyTime(),
                                "Implausible sourceClockOffsetMs (" + e.sourceClockOffsetMs() + "ms) attempted to shift timestamp across approval boundary.",
                                "PRACTICE_22_EVENTS"
                        ));
                    }
                }
            } else {
                Optional<RoleEscalation> priorEscalation = "allow".equalsIgnoreCase(e.outcome())
                        ? findPriorRoleEscalation(e.actor(), ae, unapprovedRoleChangesByActor, approvedRevocationsBySubject)
                        : Optional.empty();
                if (priorEscalation.isPresent()) {
                    RoleEscalation root = priorEscalation.get();
                    predictedLabel = "review_after_role_change";
                    String sessionNote = root.sessionId().equals(e.sessionId())
                            ? "in session " + e.sessionId()
                            : "following cross-session escalation from " + root.sessionId() + " to " + e.sessionId();
                    explanation = "Allowed access on " + e.targetService() + " directly follows unapproved role change "
                            + root.eventId() + " " + sessionNote + ".";
                    alerts.add(new AlertDto(
                            "prac-alt-" + (alertSeq++),
                            "suspicious_privilege_escalation",
                            "CRITICAL",
                            "CONFIRMED_VIOLATION",
                            e.actor(),
                            e.sourceService() + " -> " + e.targetService(),
                            List.of(root.eventId(), e.eventId()),
                            e.correlationId(),
                            e.sessionId(),
                            ae.policyTime(),
                            explanation,
                            "PRACTICE_22_EVENTS"
                    ));
                } else if (ae.implausibleClockOffset()) {
                    predictedLabel = "suspicious_clock_offset";
                    explanation = "Rejected implausible sourceClockOffsetMs (" + e.sourceClockOffsetMs()
                            + "ms, delivery delay " + ae.deliveryDelayMs()
                            + "ms): refused to shift timestamp back into historical approval window; evaluated against collector time "
                            + ae.policyTime() + ".";
                    alerts.add(new AlertDto(
                            "prac-alt-" + (alertSeq++),
                            "implausible_clock_offset",
                            "HIGH",
                            "CONFIRMED_VIOLATION",
                            e.actor(),
                            e.sourceService() + " -> " + e.targetService(),
                            List.of(e.eventId()),
                            e.correlationId(),
                            e.sessionId(),
                            ae.policyTime(),
                            explanation,
                            "PRACTICE_22_EVENTS"
                    ));
                } else if (lateralMovementEventIds.contains(e.eventId())) {
                    if ("allow".equalsIgnoreCase(e.outcome())) {
                        predictedLabel = "unexpected_service_access";
                        explanation = "Allowed unexpected service edge (" + e.sourceService() + " -> " + e.targetService()
                                + ") within multi-hop sequence by " + e.actor() + ".";
                        alerts.add(new AlertDto(
                                "prac-alt-" + (alertSeq++),
                                "unexpected_allowed_service_edge",
                                "HIGH",
                                "CONFIRMED_VIOLATION",
                                e.actor(),
                                e.sourceService() + " -> " + e.targetService(),
                                List.of(e.eventId()),
                                e.correlationId(),
                                e.sessionId(),
                                ae.policyTime(),
                                explanation,
                                "PRACTICE_22_EVENTS"
                        ));
                    } else {
                        predictedLabel = "lateral_movement_candidate";
                        explanation = "Part of multi-edge denied sequence (" + e.sourceService() + " -> " + e.targetService()
                                + ") in " + e.correlationId() + "; request was DENIED.";
                    }
                } else if (isPostRevocationExpectedDenial(e, ae.policyTime(), approvals)) {
                    predictedLabel = "routine_denial";
                    explanation = "Expected post-revocation denial on " + e.targetService()
                            + " within transition window after role expiration/revocation.";
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
                            ae.policyTime(),
                            explanation,
                            "PRACTICE_22_EVENTS"
                    ));
                } else if ("allow".equalsIgnoreCase(e.outcome()) && !isKnownNormalEdge(e, ae.policyTime(), approvals)) {
                    predictedLabel = "unexpected_service_access";
                    explanation = "Allowed access on unexpected non-normal service edge "
                            + e.sourceService() + " -> " + e.targetService()
                            + " for actor " + e.actor() + " (role " + e.roleAfter() + ").";
                    alerts.add(new AlertDto(
                            "prac-alt-" + (alertSeq++),
                            "unexpected_allowed_service_edge",
                            "HIGH",
                            "CONFIRMED_VIOLATION",
                            e.actor(),
                            e.sourceService() + " -> " + e.targetService(),
                            List.of(e.eventId()),
                            e.correlationId(),
                            e.sessionId(),
                            ae.policyTime(),
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

    private boolean isImplausibleClockOffset(
            PracticeEvent evt,
            Instant corrected,
            long delayMs,
            List<ApprovalChange> approvals
    ) {
        if (Math.abs(evt.sourceClockOffsetMs()) > MAX_PLAUSIBLE_CLOCK_OFFSET_MS) {
            return true;
        }
        if (delayMs < 0) {
            return true;
        }
        if (evt.sourceClockOffsetMs() != 0 && delayMs > MAX_PLAUSIBLE_OFFSET_DELAY_MS) {
            return true;
        }
        // Prevent smaller positive offsets from dragging post-expiration events back into expired windows,
        // and reject negative offsets that shift events forward across grant validFromUtc or revoke effectiveAtUtc boundaries.
        if (evt.sourceClockOffsetMs() > 0) {
            for (ApprovalChange a : approvals) {
                if ("grant_role".equals(a.operation())
                        && a.subject().equals(evt.actor())
                        && a.validUntilUtc() != null
                        && corrected.isBefore(a.validUntilUtc())
                        && evt.receivedTimeUtc().isAfter(a.validUntilUtc().plusSeconds(5))) {
                    return true;
                }
            }
        } else if (evt.sourceClockOffsetMs() < 0) {
            for (ApprovalChange a : approvals) {
                if ("grant_role".equals(a.operation())
                        && a.subject().equals(evt.actor())
                        && a.validFromUtc() != null
                        && evt.eventTimeUtc().isBefore(a.validFromUtc())
                        && !corrected.isBefore(a.validFromUtc())) {
                    return true;
                }
                if ("revoke_role".equals(a.operation())
                        && a.subject().equals(evt.actor())
                        && a.effectiveAtUtc() != null
                        && evt.eventTimeUtc().isBefore(a.effectiveAtUtc())
                        && !corrected.isBefore(a.effectiveAtUtc())) {
                    return true;
                }
            }
        }
        return false;
    }

    private AlertDto buildLateralAlert(
            List<AnnotatedEvent> cluster,
            int seq,
            boolean slowHorizon,
            Set<String> lateralMovementEventIds
    ) {
        List<String> ids = cluster.stream().map(a -> a.raw().eventId()).toList();
        lateralMovementEventIds.addAll(ids);
        String path = buildServicePath(cluster);
        PracticeEvent first = cluster.get(0).raw();
        boolean hasAllowedHop = cluster.stream()
                .anyMatch(a -> "allow".equalsIgnoreCase(a.raw().outcome()));

        Set<String> sessions = new LinkedHashSet<>();
        Set<String> correlations = new LinkedHashSet<>();
        for (AnnotatedEvent item : cluster) {
            if (item.raw().sessionId() != null && !item.raw().sessionId().isBlank()) {
                sessions.add(item.raw().sessionId());
            }
            if (item.raw().correlationId() != null && !item.raw().correlationId().isBlank()) {
                correlations.add(item.raw().correlationId());
            }
        }

        String sessionSummary = sessions.size() == 1 ? first.sessionId() : String.join(",", sessions);
        String corrSummary = correlations.size() == 1 ? first.correlationId() : String.join(",", correlations);
        String windowDesc = slowHorizon ? "24h slow-and-low horizon" : (LATERAL_MOVEMENT_WINDOW_MS / 1000) + "s window";

        String explanation = hasAllowedHop
                ? cluster.size() + " sequential unexpected service edges by " + first.actor()
                        + " within " + windowDesc + " (session " + sessionSummary + " / flow " + corrSummary
                        + "). Includes unexpected ALLOWED edge(s); classified as confirmed multi-hop violation."
                : cluster.size() + " sequential unexpected service edges grouped in session "
                        + sessionSummary + " / " + corrSummary + " (" + windowDesc
                        + "). All requests were DENIED; classified as candidate lateral-movement reconnaissance, NOT successful compromise.";

        return new AlertDto(
                "prac-alt-" + seq,
                "lateral_movement_candidate",
                hasAllowedHop ? "CRITICAL" : "HIGH",
                hasAllowedHop ? "CONFIRMED_VIOLATION" : "DENIED_ATTEMPT",
                first.actor(),
                path,
                ids,
                corrSummary,
                sessionSummary,
                cluster.get(cluster.size() - 1).correctedTime(),
                explanation,
                "PRACTICE_22_EVENTS"
        );
    }

    private Optional<RoleEscalation> findPriorRoleEscalation(
            String actor,
            AnnotatedEvent ae,
            Map<String, List<RoleEscalation>> byActor,
            Map<String, List<RoleRevocation>> revocationsBySubject
    ) {
        List<RoleEscalation> list = byActor.get(actor);
        if (list == null || list.isEmpty()) {
            return Optional.empty();
        }
        List<RoleRevocation> revocations = revocationsBySubject.getOrDefault(actor, List.of());
        RoleEscalation matched = null;
        for (RoleEscalation rc : list) {
            if (rc.eventId().equals(ae.raw().eventId())) {
                continue;
            }
            boolean chronologicallyAfter = ae.policyTime().isAfter(rc.policyTime())
                    || (!ae.policyTime().isBefore(rc.policyTime()) && ae.orderIndex() > rc.orderIndex());
            if (!chronologicallyAfter) {
                continue;
            }
            boolean clearedByRevocation = revocations.stream().anyMatch(rev -> {
                boolean revAfterRc = rev.policyTime().isAfter(rc.policyTime())
                        || (!rev.policyTime().isBefore(rc.policyTime()) && rev.orderIndex() > rc.orderIndex());
                boolean aeAfterRev = ae.policyTime().isAfter(rev.policyTime())
                        || (!ae.policyTime().isBefore(rev.policyTime()) && ae.orderIndex() > rev.orderIndex());
                return revAfterRc && aeAfterRev;
            });
            if (!clearedByRevocation) {
                matched = rc;
            }
        }
        return Optional.ofNullable(matched);
    }

    private List<List<AnnotatedEvent>> clusterByBoundedWindow(List<AnnotatedEvent> sorted, long windowMs) {
        List<List<AnnotatedEvent>> clusters = new ArrayList<>();
        if (sorted.isEmpty()) {
            return clusters;
        }
        List<AnnotatedEvent> current = new ArrayList<>();
        current.add(sorted.get(0));
        for (int i = 1; i < sorted.size(); i++) {
            AnnotatedEvent prev = sorted.get(i - 1);
            AnnotatedEvent curr = sorted.get(i);
            long gapMs = Duration.between(prev.policyTime(), curr.policyTime()).toMillis();
            if (gapMs <= windowMs) {
                current.add(curr);
            } else {
                clusters.add(current);
                current = new ArrayList<>();
                current.add(curr);
            }
        }
        clusters.add(current);
        return clusters;
    }

    private Optional<ApprovalChange> findMatchingGrantApproval(
            PracticeEvent event,
            Instant policyTime,
            List<ApprovalChange> approvals
    ) {
        return approvals.stream()
                .filter(a -> "grant_role".equals(a.operation()))
                .filter(a -> a.subject().equals(event.actor()))
                .filter(a -> a.role().equals(event.roleAfter()))
                .filter(a -> event.approvalId().isBlank() || a.approvalId().equals(event.approvalId()))
                .filter(a -> a.validFromUtc() != null && !policyTime.isBefore(a.validFromUtc()))
                .filter(a -> a.validUntilUtc() == null || policyTime.isBefore(a.validUntilUtc()))
                .filter(a -> !isRoleRevokedAt(event.actor(), event.roleAfter(), policyTime, approvals))
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

    private boolean isRoleRevokedAt(
            String actor,
            String role,
            Instant policyTime,
            List<ApprovalChange> approvals
    ) {
        return approvals.stream()
                .filter(a -> "revoke_role".equals(a.operation()))
                .filter(a -> a.subject().equals(actor))
                .filter(a -> role == null || role.isBlank() || role.equals(a.role()))
                .anyMatch(a -> a.effectiveAtUtc() != null && !policyTime.isBefore(a.effectiveAtUtc()));
    }

    private boolean isPostRevocationExpectedDenial(
            PracticeEvent event,
            Instant policyTime,
            List<ApprovalChange> approvals
    ) {
        if (!"deny".equalsIgnoreCase(event.outcome())) {
            return false;
        }
        boolean withinTransitionWindow = approvals.stream()
                .filter(a -> "revoke_role".equals(a.operation()))
                .filter(a -> a.subject().equals(event.actor()))
                .anyMatch(a -> a.effectiveAtUtc() != null
                        && !policyTime.isBefore(a.effectiveAtUtc())
                        && !policyTime.isAfter(a.effectiveAtUtc().plusSeconds(POST_REVOCATION_TRANSITION_WINDOW_SECONDS)));
        if (!withinTransitionWindow) {
            return false;
        }
        return approvals.stream()
                .filter(a -> "grant_role".equals(a.operation()))
                .filter(a -> a.subject().equals(event.actor()))
                .anyMatch(a -> a.scope().contains(event.targetService()));
    }

    private boolean isKnownNormalEdge(
            PracticeEvent event,
            Instant policyTime,
            List<ApprovalChange> approvals
    ) {
        String src = event.sourceService();
        String dst = event.targetService();
        String role = event.roleAfter();
        boolean isServiceAccount = event.actor() != null && event.actor().startsWith("svc-");
        boolean isExpectedPortalRole = "viewer".equals(role)
                || "report-reader".equals(role)
                || "operator".equals(role)
                || "USER".equals(role)
                || "ADMIN".equals(role);

        if ("portal".equals(src) && ("identity".equals(dst) || "catalog".equals(dst))) {
            return !isServiceAccount && isExpectedPortalRole;
        }
        if ("admin-console".equals(src) && "identity".equals(dst) && "operator".equals(role)) {
            return true;
        }
        if ("svc-report-worker".equals(event.actor()) && "reports".equals(src) && "catalog".equals(dst)) {
            return true;
        }
        if ("report-reader".equals(role) && "portal".equals(src)) {
            return approvals.stream()
                    .filter(a -> "grant_role".equals(a.operation()))
                    .filter(a -> a.subject().equals(event.actor()))
                    .filter(a -> a.role().equals(role))
                    .filter(a -> a.scope().contains(dst))
                    .filter(a -> !isRoleRevokedAt(event.actor(), role, policyTime, approvals))
                    .anyMatch(a -> (a.validFromUtc() == null || !policyTime.isBefore(a.validFromUtc()))
                            && (a.validUntilUtc() == null || policyTime.isBefore(a.validUntilUtc())));
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
