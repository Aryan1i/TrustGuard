package com.trustguard.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record DetectionEvaluationResponse(
        String datasetSource,
        int totalEventsProcessed,
        boolean labelsUsedInDetectionLogic,
        List<ClassifiedEventDto> classifiedEvents,
        List<AlertDto> generatedAlerts,
        EvaluationMetricsDto postDetectionEvaluation,
        String limitationNotice
) {
    public record ClassifiedEventDto(
            String eventId,
            String actor,
            String sourceService,
            String targetService,
            String action,
            String outcome,
            Instant rawEventTimeUtc,
            long sourceClockOffsetMs,
            Instant correctedEventTimeUtc,
            Instant receivedTimeUtc,
            long deliveryDelayMs,
            boolean outOfOrderArrival,
            String predictedLabel,
            String explanation
    ) {
    }

    public record AlertDto(
            String alertUid,
            String ruleName,
            String severity,
            String outcomeClassification,
            String actor,
            String servicePath,
            List<String> eventIds,
            String correlationId,
            String sessionId,
            Instant timestamp,
            String explanation,
            String datasetSource
    ) {
    }

    public record EvaluationMetricsDto(
            int sampleSize,
            int truePositives,
            int falsePositives,
            int trueNegatives,
            int falseNegatives,
            int exactLabelMatches,
            double precision,
            double recall,
            double f1Score,
            double falseAlertsPer1000Benign,
            Map<String, String> mismatches
    ) {
    }
}
