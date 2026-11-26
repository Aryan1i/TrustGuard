package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "devices")
public class DeviceEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "device_uid", nullable = false, unique = true, length = 64)
    private String deviceUid;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "owner_user_id", nullable = false)
    private UserEntity owner;

    @Column(name = "device_name", nullable = false, length = 120)
    private String deviceName;

    @Column(name = "public_key_b64", nullable = false, columnDefinition = "TEXT")
    private String publicKeyB64;

    @Column(name = "public_key_fingerprint", nullable = false, length = 64)
    private String publicKeyFingerprint;

    @Column(name = "key_reference", nullable = false, length = 180)
    private String keyReference;

    @Column(name = "key_algorithm", nullable = false, length = 80)
    private String keyAlgorithm;

    @Column(name = "signing_public_key_b64", nullable = false, columnDefinition = "TEXT")
    private String signingPublicKeyB64;

    @Column(nullable = false, length = 32)
    private String status;

    @Column(name = "enrolled_at", nullable = false)
    private Instant enrolledAt = Instant.now();

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt = Instant.now();

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "replaced_by_device_id")
    private Long replacedByDeviceId;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getDeviceUid() { return deviceUid; }
    public void setDeviceUid(String deviceUid) { this.deviceUid = deviceUid; }
    public UserEntity getOwner() { return owner; }
    public void setOwner(UserEntity owner) { this.owner = owner; }
    public String getDeviceName() { return deviceName; }
    public void setDeviceName(String deviceName) { this.deviceName = deviceName; }
    public String getPublicKeyB64() { return publicKeyB64; }
    public void setPublicKeyB64(String publicKeyB64) { this.publicKeyB64 = publicKeyB64; }
    public String getPublicKeyFingerprint() { return publicKeyFingerprint; }
    public void setPublicKeyFingerprint(String publicKeyFingerprint) { this.publicKeyFingerprint = publicKeyFingerprint; }
    public String getKeyReference() { return keyReference; }
    public void setKeyReference(String keyReference) { this.keyReference = keyReference; }
    public String getKeyAlgorithm() { return keyAlgorithm; }
    public void setKeyAlgorithm(String keyAlgorithm) { this.keyAlgorithm = keyAlgorithm; }
    public String getSigningPublicKeyB64() { return signingPublicKeyB64; }
    public void setSigningPublicKeyB64(String signingPublicKeyB64) { this.signingPublicKeyB64 = signingPublicKeyB64; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public Instant getEnrolledAt() { return enrolledAt; }
    public void setEnrolledAt(Instant enrolledAt) { this.enrolledAt = enrolledAt; }
    public Instant getLastSeenAt() { return lastSeenAt; }
    public void setLastSeenAt(Instant lastSeenAt) { this.lastSeenAt = lastSeenAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
    public Long getReplacedByDeviceId() { return replacedByDeviceId; }
    public void setReplacedByDeviceId(Long replacedByDeviceId) { this.replacedByDeviceId = replacedByDeviceId; }
}
