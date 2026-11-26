package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(
        name = "node_key_acknowledgements",
        uniqueConstraints = @UniqueConstraint(name = "uk_node_key_ack", columnNames = {"key_version_id", "node_id"})
)
public class NodeKeyAcknowledgementEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "key_version_id", nullable = false)
    private KeyVersionEntity keyVersion;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "node_id", nullable = false)
    private SimulatedNodeEntity node;

    @Column(name = "ack_status", nullable = false, length = 32)
    private String ackStatus;

    @Column(name = "acknowledged_at")
    private Instant acknowledgedAt;

    @Column(name = "detail_message", length = 255)
    private String detailMessage;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public KeyVersionEntity getKeyVersion() { return keyVersion; }
    public void setKeyVersion(KeyVersionEntity keyVersion) { this.keyVersion = keyVersion; }
    public SimulatedNodeEntity getNode() { return node; }
    public void setNode(SimulatedNodeEntity node) { this.node = node; }
    public String getAckStatus() { return ackStatus; }
    public void setAckStatus(String ackStatus) { this.ackStatus = ackStatus; }
    public Instant getAcknowledgedAt() { return acknowledgedAt; }
    public void setAcknowledgedAt(Instant acknowledgedAt) { this.acknowledgedAt = acknowledgedAt; }
    public String getDetailMessage() { return detailMessage; }
    public void setDetailMessage(String detailMessage) { this.detailMessage = detailMessage; }
}
