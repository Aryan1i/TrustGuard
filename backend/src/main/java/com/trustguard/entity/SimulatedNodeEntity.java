package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "simulated_nodes")
public class SimulatedNodeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "node_code", nullable = false, unique = true, length = 64)
    private String nodeCode;

    @Column(name = "node_name", nullable = false, length = 120)
    private String nodeName;

    @Column(nullable = false, length = 64)
    private String region;

    @Column(nullable = false, length = 32)
    private String status;

    @Column(name = "current_key_version", nullable = false)
    private int currentKeyVersion;

    @Column(name = "current_revocation_version", nullable = false)
    private long currentRevocationVersion;

    @Column(name = "last_heartbeat_at", nullable = false)
    private Instant lastHeartbeatAt = Instant.now();

    @Column(name = "last_revocation_enforced_at")
    private Instant lastRevocationEnforcedAt;

    @Column(name = "last_propagation_ms")
    private Long lastPropagationMs;

    @Column(name = "simulate_ack_failure", nullable = false)
    private boolean simulateAckFailure = false;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getNodeCode() { return nodeCode; }
    public void setNodeCode(String nodeCode) { this.nodeCode = nodeCode; }
    public String getNodeName() { return nodeName; }
    public void setNodeName(String nodeName) { this.nodeName = nodeName; }
    public String getRegion() { return region; }
    public void setRegion(String region) { this.region = region; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public int getCurrentKeyVersion() { return currentKeyVersion; }
    public void setCurrentKeyVersion(int currentKeyVersion) { this.currentKeyVersion = currentKeyVersion; }
    public long getCurrentRevocationVersion() { return currentRevocationVersion; }
    public void setCurrentRevocationVersion(long currentRevocationVersion) { this.currentRevocationVersion = currentRevocationVersion; }
    public Instant getLastHeartbeatAt() { return lastHeartbeatAt; }
    public void setLastHeartbeatAt(Instant lastHeartbeatAt) { this.lastHeartbeatAt = lastHeartbeatAt; }
    public Instant getLastRevocationEnforcedAt() { return lastRevocationEnforcedAt; }
    public void setLastRevocationEnforcedAt(Instant lastRevocationEnforcedAt) { this.lastRevocationEnforcedAt = lastRevocationEnforcedAt; }
    public Long getLastPropagationMs() { return lastPropagationMs; }
    public void setLastPropagationMs(Long lastPropagationMs) { this.lastPropagationMs = lastPropagationMs; }
    public boolean isSimulateAckFailure() { return simulateAckFailure; }
    public void setSimulateAckFailure(boolean simulateAckFailure) { this.simulateAckFailure = simulateAckFailure; }
}
