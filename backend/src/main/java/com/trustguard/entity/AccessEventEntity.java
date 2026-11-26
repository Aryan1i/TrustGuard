package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "access_events")
public class AccessEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id", nullable = false, unique = true, length = 96)
    private String requestId;

    @Column(name = "actor_username", nullable = false, length = 64)
    private String actorUsername;

    @Column(name = "authenticated_principal", nullable = false, length = 64)
    private String authenticatedPrincipal;

    @Column(name = "simulation_mode", nullable = false)
    private boolean simulationMode;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "device_id")
    private DeviceEntity device;

    @Column(name = "source_service", nullable = false, length = 64)
    private String sourceService;

    @Column(name = "target_service", nullable = false, length = 64)
    private String targetService;

    @Column(name = "resource_key", nullable = false, length = 80)
    private String resourceKey;

    @Column(nullable = false, length = 40)
    private String action;

    @Column(nullable = false, length = 16)
    private String decision;

    @Column(name = "decision_reason", nullable = false, length = 255)
    private String decisionReason;

    @Column(name = "key_version_used", nullable = false)
    private int keyVersionUsed;

    @Column(name = "node_code", length = 64)
    private String nodeCode;

    @Column(name = "timestamp_utc", nullable = false)
    private Instant timestampUtc = Instant.now();

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }
    public String getActorUsername() { return actorUsername; }
    public void setActorUsername(String actorUsername) { this.actorUsername = actorUsername; }
    public String getAuthenticatedPrincipal() { return authenticatedPrincipal; }
    public void setAuthenticatedPrincipal(String authenticatedPrincipal) { this.authenticatedPrincipal = authenticatedPrincipal; }
    public boolean isSimulationMode() { return simulationMode; }
    public void setSimulationMode(boolean simulationMode) { this.simulationMode = simulationMode; }
    public DeviceEntity getDevice() { return device; }
    public void setDevice(DeviceEntity device) { this.device = device; }
    public String getSourceService() { return sourceService; }
    public void setSourceService(String sourceService) { this.sourceService = sourceService; }
    public String getTargetService() { return targetService; }
    public void setTargetService(String targetService) { this.targetService = targetService; }
    public String getResourceKey() { return resourceKey; }
    public void setResourceKey(String resourceKey) { this.resourceKey = resourceKey; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getDecision() { return decision; }
    public void setDecision(String decision) { this.decision = decision; }
    public String getDecisionReason() { return decisionReason; }
    public void setDecisionReason(String decisionReason) { this.decisionReason = decisionReason; }
    public int getKeyVersionUsed() { return keyVersionUsed; }
    public void setKeyVersionUsed(int keyVersionUsed) { this.keyVersionUsed = keyVersionUsed; }
    public String getNodeCode() { return nodeCode; }
    public void setNodeCode(String nodeCode) { this.nodeCode = nodeCode; }
    public Instant getTimestampUtc() { return timestampUtc; }
    public void setTimestampUtc(Instant timestampUtc) { this.timestampUtc = timestampUtc; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
