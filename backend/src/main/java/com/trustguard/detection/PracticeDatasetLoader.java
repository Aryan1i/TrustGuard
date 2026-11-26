package com.trustguard.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.detection.PracticeModels.ApprovalChange;
import com.trustguard.detection.PracticeModels.ExpectedLabel;
import com.trustguard.detection.PracticeModels.PracticeEvent;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Component
public class PracticeDatasetLoader {

    private final ObjectMapper objectMapper;

    public PracticeDatasetLoader(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public List<PracticeEvent> loadEvents() {
        ClassPathResource resource = new ClassPathResource("practice/events.csv");
        try (Reader reader = new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build().parse(reader)) {
            List<PracticeEvent> events = new ArrayList<>();
            for (CSVRecord record : parser) {
                events.add(new PracticeEvent(
                        record.get("event_id").trim(),
                        Instant.parse(record.get("event_time_utc").trim()),
                        Instant.parse(record.get("received_time_utc").trim()),
                        Long.parseLong(record.get("source_clock_offset_ms").trim()),
                        record.get("actor").trim(),
                        record.get("source_service").trim(),
                        record.get("target_service").trim(),
                        record.get("action").trim(),
                        record.get("role_before").trim(),
                        record.get("role_after").trim(),
                        record.get("outcome").trim(),
                        record.get("approval_id").trim(),
                        record.get("session_id").trim(),
                        record.get("correlation_id").trim()
                ));
            }
            return events;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load practice/events.csv", e);
        }
    }

    public List<ApprovalChange> loadApprovals() {
        ClassPathResource resource = new ClassPathResource("practice/approvals.json");
        try {
            JsonNode root = objectMapper.readTree(resource.getInputStream());
            JsonNode changesNode = root.path("changes");
            List<ApprovalChange> changes = new ArrayList<>();
            for (JsonNode node : changesNode) {
                List<String> scope = new ArrayList<>();
                if (node.has("scope") && node.get("scope").isArray()) {
                    for (JsonNode s : node.get("scope")) {
                        scope.add(s.asText());
                    }
                }
                Instant validFrom = node.hasNonNull("valid_from_utc")
                        ? Instant.parse(node.get("valid_from_utc").asText())
                        : null;
                Instant validUntil = node.hasNonNull("valid_until_utc")
                        ? Instant.parse(node.get("valid_until_utc").asText())
                        : null;
                Instant effectiveAt = node.hasNonNull("effective_at_utc")
                        ? Instant.parse(node.get("effective_at_utc").asText())
                        : null;
                changes.add(new ApprovalChange(
                        node.get("approval_id").asText(),
                        node.get("approved_by").asText(),
                        node.get("subject").asText(),
                        node.get("operation").asText(),
                        node.get("role").asText(),
                        scope,
                        validFrom,
                        validUntil,
                        effectiveAt
                ));
            }
            return changes;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load practice/approvals.json", e);
        }
    }

    /**
     * Strictly for post-detection accuracy evaluation. Never call from detection logic.
     */
    public List<ExpectedLabel> loadLabelsOnlyForPostEvaluation() {
        ClassPathResource resource = new ClassPathResource("practice/labels.csv");
        try (Reader reader = new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build().parse(reader)) {
            List<ExpectedLabel> labels = new ArrayList<>();
            for (CSVRecord record : parser) {
                labels.add(new ExpectedLabel(
                        record.get("event_id").trim(),
                        record.get("label").trim(),
                        record.get("reason").trim()
                ));
            }
            return labels;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load practice/labels.csv", e);
        }
    }
}
