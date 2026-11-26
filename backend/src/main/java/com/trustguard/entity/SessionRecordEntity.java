package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "session_records")
public class SessionRecordEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "session_id", nullable = false, unique = true, length = 80)
    private String sessionId;

    @Column(name = "actor_username", nullable = false, length = 64)
    private String actorUsername;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "device_id")
    private DeviceEntity device;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "peer_device_id")
    private DeviceEntity peerDevice;

    @Column(nullable = false, length = 32)
    private String status;

    @Column(name = "auth_token_hash", nullable = false, length = 64)
    private String authTokenHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "last_active_at", nullable = false)
    private Instant lastActiveAt = Instant.now();

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "resumed_count", nullable = false)
    private int resumedCount = 0;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    public String getActorUsername() { return actorUsername; }
    public void setActorUsername(String actorUsername) { this.actorUsername = actorUsername; }
    public DeviceEntity getDevice() { return device; }
    public void setDevice(DeviceEntity device) { this.device = device; }
    public DeviceEntity getPeerDevice() { return peerDevice; }
    public void setPeerDevice(DeviceEntity peerDevice) { this.peerDevice = peerDevice; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getAuthTokenHash() { return authTokenHash; }
    public void setAuthTokenHash(String authTokenHash) { this.authTokenHash = authTokenHash; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getLastActiveAt() { return lastActiveAt; }
    public void setLastActiveAt(Instant lastActiveAt) { this.lastActiveAt = lastActiveAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public int getResumedCount() { return resumedCount; }
    public void setResumedCount(int resumedCount) { this.resumedCount = resumedCount; }
}
