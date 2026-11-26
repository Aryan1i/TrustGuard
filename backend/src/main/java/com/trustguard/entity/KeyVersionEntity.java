package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(
        name = "key_versions",
        uniqueConstraints = @UniqueConstraint(name = "uk_key_alias_version", columnNames = {"key_alias", "version_number"})
)
public class KeyVersionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "key_alias", nullable = false, length = 80)
    private String keyAlias;

    @Column(name = "version_number", nullable = false)
    private int versionNumber;

    @Column(nullable = false, length = 80)
    private String algorithm;

    @Column(nullable = false, length = 32)
    private String status;

    @Column(name = "public_key_b64", nullable = false, columnDefinition = "TEXT")
    private String publicKeyB64;

    @Column(name = "public_key_fingerprint", nullable = false, length = 64)
    private String publicKeyFingerprint;

    @Column(name = "key_reference", nullable = false, length = 180)
    private String keyReference;

    @Column(name = "grace_period_seconds", nullable = false)
    private int gracePeriodSeconds = 60;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "distributed_at")
    private Instant distributedAt;

    @Column(name = "committed_at")
    private Instant committedAt;

    @Column(name = "activation_time")
    private Instant activationTime;

    @Column(name = "grace_until")
    private Instant graceUntil;

    @Column(name = "cutoff_time")
    private Instant cutoffTime;

    @Column(name = "failure_reason", length = 255)
    private String failureReason;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getKeyAlias() { return keyAlias; }
    public void setKeyAlias(String keyAlias) { this.keyAlias = keyAlias; }
    public int getVersionNumber() { return versionNumber; }
    public void setVersionNumber(int versionNumber) { this.versionNumber = versionNumber; }
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getPublicKeyB64() { return publicKeyB64; }
    public void setPublicKeyB64(String publicKeyB64) { this.publicKeyB64 = publicKeyB64; }
    public String getPublicKeyFingerprint() { return publicKeyFingerprint; }
    public void setPublicKeyFingerprint(String publicKeyFingerprint) { this.publicKeyFingerprint = publicKeyFingerprint; }
    public String getKeyReference() { return keyReference; }
    public void setKeyReference(String keyReference) { this.keyReference = keyReference; }
    public int getGracePeriodSeconds() { return gracePeriodSeconds; }
    public void setGracePeriodSeconds(int gracePeriodSeconds) { this.gracePeriodSeconds = gracePeriodSeconds; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getDistributedAt() { return distributedAt; }
    public void setDistributedAt(Instant distributedAt) { this.distributedAt = distributedAt; }
    public Instant getCommittedAt() { return committedAt; }
    public void setCommittedAt(Instant committedAt) { this.committedAt = committedAt; }
    public Instant getActivationTime() { return activationTime; }
    public void setActivationTime(Instant activationTime) { this.activationTime = activationTime; }
    public Instant getGraceUntil() { return graceUntil; }
    public void setGraceUntil(Instant graceUntil) { this.graceUntil = graceUntil; }
    public Instant getCutoffTime() { return cutoffTime; }
    public void setCutoffTime(Instant cutoffTime) { this.cutoffTime = cutoffTime; }
    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
}
