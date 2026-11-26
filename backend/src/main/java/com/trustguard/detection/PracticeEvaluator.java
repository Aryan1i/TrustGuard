package com.trustguard.detection;

import com.trustguard.detection.PracticeModels.ExpectedLabel;
import com.trustguard.dto.DetectionEvaluationResponse.ClassifiedEventDto;
import com.trustguard.dto.DetectionEvaluationResponse.EvaluationMetricsDto;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Post-detection evaluator comparing deterministic engine outputs against practice/labels.csv.
 * Never invoked before or inside detection logic.
 */
@Service
public class PracticeEvaluator {

    private static final Set<String> SECURITY_ALERT_LABELS = Set.of(
            "unexpected_role_change",
            "review_after_role_change",
            "lateral_movement_candidate",
            "isolated_denial",
            "unexpected_service_access",
            "suspicious_clock_offset"
    );

    public EvaluationMetricsDto evaluateAgainstLabels(
            List<ClassifiedEventDto> classifiedEvents,
            List<ExpectedLabel> groundTruthLabels
    ) {
        Map<String, ExpectedLabel> expectedMap = groundTruthLabels.stream()
                .collect(Collectors.toMap(ExpectedLabel::eventId, l -> l));

        int tp = 0;
        int fp = 0;
        int tn = 0;
        int fn = 0;
        int exactMatches = 0;
        Map<String, String> mismatches = new LinkedHashMap<>();

        for (ClassifiedEventDto evt : classifiedEvents) {
            ExpectedLabel expected = expectedMap.get(evt.eventId());
            if (expected == null) {
                continue;
            }
            String predLabel = evt.predictedLabel();
            String expLabel = expected.label();
            if (predLabel.equals(expLabel)) {
                exactMatches++;
            } else {
                mismatches.put(evt.eventId(), "predicted=" + predLabel + ", expected=" + expLabel);
            }

            boolean predPositive = SECURITY_ALERT_LABELS.contains(predLabel);
            boolean expPositive = SECURITY_ALERT_LABELS.contains(expLabel);
            if (predPositive && expPositive) {
                tp++;
            } else if (predPositive) {
                fp++;
            } else if (expPositive) {
                fn++;
            } else {
                tn++;
            }
        }

        double precision = (tp + fp) == 0 ? 1.0 : (double) tp / (tp + fp);
        double recall = (tp + fn) == 0 ? 1.0 : (double) tp / (tp + fn);
        double f1 = (precision + recall) == 0.0 ? 0.0 : (2.0 * precision * recall) / (precision + recall);
        int benignCount = tn + fp;
        double falsePer1000 = benignCount == 0 ? 0.0 : ((double) fp / benignCount) * 1000.0;

        return new EvaluationMetricsDto(
                classifiedEvents.size(),
                tp,
                fp,
                tn,
                fn,
                exactMatches,
                round4(precision),
                round4(recall),
                round4(f1),
                round4(falsePer1000),
                mismatches
        );
    }

    private double round4(double v) {
        return Math.round(v * 10000.0) / 10000.0;
    }
}
