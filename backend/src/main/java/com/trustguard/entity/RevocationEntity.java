package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "revocations")
public class RevocationEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "revocation_version", nullable = false, unique = true)
    private long revocationVersion;

    @Column(name = "target_type", nullable = false, length = 32)
    private String targetType;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "device_id")
    private DeviceEntity device;

    @Column(nullable = false, length = 64)
    private String username;

    @Column(nullable = false, length = 255)
    private String reason;

    @Column(name = "initiated_by", nullable = false, length = 64)
    private String initiatedBy;

    @Column(name = "revoked_at", nullable = false)
    private Instant revokedAt;

    @Column(name = "propagation_completed_at", nullable = false)
    private Instant propagationCompletedAt;

    @Column(name = "propagation_latency_ms", nullable = false)
    private long propagationLatencyMs;

    @Column(name = "nodes_enforced_count", nullable = false)
    private int nodesEnforcedCount;

    @Column(name = "total_nodes_count", nullable = false)
    private int totalNodesCount;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public long getRevocationVersion() { return revocationVersion; }
    public void setRevocationVersion(long revocationVersion) { this.revocationVersion = revocationVersion; }
    public String getTargetType() { return targetType; }
    public void setTargetType(String targetType) { this.targetType = targetType; }
    public DeviceEntity getDevice() { return device; }
    public void setDevice(DeviceEntity device) { this.device = device; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public String getInitiatedBy() { return initiatedBy; }
    public void setInitiatedBy(String initiatedBy) { this.initiatedBy = initiatedBy; }
    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
    public Instant getPropagationCompletedAt() { return propagationCompletedAt; }
    public void setPropagationCompletedAt(Instant propagationCompletedAt) { this.propagationCompletedAt = propagationCompletedAt; }
    public long getPropagationLatencyMs() { return propagationLatencyMs; }
    public void setPropagationLatencyMs(long propagationLatencyMs) { this.propagationLatencyMs = propagationLatencyMs; }
    public int getNodesEnforcedCount() { return nodesEnforcedCount; }
    public void setNodesEnforcedCount(int nodesEnforcedCount) { this.nodesEnforcedCount = nodesEnforcedCount; }
    public int getTotalNodesCount() { return totalNodesCount; }
    public void setTotalNodesCount(int totalNodesCount) { this.totalNodesCount = totalNodesCount; }
}
