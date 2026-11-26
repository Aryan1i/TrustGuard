package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "security_alerts")
public class SecurityAlertEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "alert_uid", nullable = false, unique = true, length = 96)
    private String alertUid;

    @Column(name = "rule_name", nullable = false, length = 80)
    private String ruleName;

    @Column(nullable = false, length = 24)
    private String severity;

    @Column(name = "outcome_classification", nullable = false, length = 32)
    private String outcomeClassification;

    @Column(nullable = false, length = 64)
    private String actor;

    @Column(name = "service_path", nullable = false, length = 255)
    private String servicePath;

    @Column(name = "event_ids_json", nullable = false, columnDefinition = "TEXT")
    private String eventIdsJson;

    @Column(name = "correlation_id", length = 64)
    private String correlationId;

    @Column(name = "session_id", length = 64)
    private String sessionId;

    @Column(name = "source_event_time_utc")
    private Instant sourceEventTimeUtc;

    @Column(name = "detected_at", nullable = false)
    private Instant detectedAt = Instant.now();

    @Column(name = "detection_latency_ms", nullable = false)
    private long detectionLatencyMs = 0L;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String explanation;

    @Column(name = "dataset_source", nullable = false, length = 64)
    private String datasetSource = "LIVE_RUNTIME";

    @Column(nullable = false)
    private boolean resolved = false;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getAlertUid() { return alertUid; }
    public void setAlertUid(String alertUid) { this.alertUid = alertUid; }
    public String getRuleName() { return ruleName; }
    public void setRuleName(String ruleName) { this.ruleName = ruleName; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getOutcomeClassification() { return outcomeClassification; }
    public void setOutcomeClassification(String outcomeClassification) { this.outcomeClassification = outcomeClassification; }
    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }
    public String getServicePath() { return servicePath; }
    public void setServicePath(String servicePath) { this.servicePath = servicePath; }
    public String getEventIdsJson() { return eventIdsJson; }
    public void setEventIdsJson(String eventIdsJson) { this.eventIdsJson = eventIdsJson; }
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    public Instant getSourceEventTimeUtc() { return sourceEventTimeUtc; }
    public void setSourceEventTimeUtc(Instant sourceEventTimeUtc) { this.sourceEventTimeUtc = sourceEventTimeUtc; }
    public Instant getDetectedAt() { return detectedAt; }
    public void setDetectedAt(Instant detectedAt) { this.detectedAt = detectedAt; }
    public long getDetectionLatencyMs() { return detectionLatencyMs; }
    public void setDetectionLatencyMs(long detectionLatencyMs) { this.detectionLatencyMs = detectionLatencyMs; }
    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }
    public String getDatasetSource() { return datasetSource; }
    public void setDatasetSource(String datasetSource) { this.datasetSource = datasetSource; }
    public boolean isResolved() { return resolved; }
    public void setResolved(boolean resolved) { this.resolved = resolved; }
}
