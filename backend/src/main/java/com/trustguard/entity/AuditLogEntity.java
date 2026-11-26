package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_logs")
public class AuditLogEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id", nullable = false, unique = true, length = 96)
    private String eventId;

    @Column(name = "seq_number", nullable = false, unique = true)
    private long seqNumber;

    @Column(nullable = false, length = 64)
    private String actor;

    @Column(nullable = false, length = 80)
    private String action;

    @Column(nullable = false, length = 128)
    private String resource;

    @Column(nullable = false, length = 512)
    private String detail;

    @Column(name = "event_timestamp_utc", nullable = false)
    private Instant eventTimestampUtc;

    @Column(name = "prev_hash", nullable = false, length = 64)
    private String prevHash;

    @Column(name = "current_hash", nullable = false, length = 64)
    private String currentHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
    public long getSeqNumber() { return seqNumber; }
    public void setSeqNumber(long seqNumber) { this.seqNumber = seqNumber; }
    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getResource() { return resource; }
    public void setResource(String resource) { this.resource = resource; }
    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }
    public Instant getEventTimestampUtc() { return eventTimestampUtc; }
    public void setEventTimestampUtc(Instant eventTimestampUtc) { this.eventTimestampUtc = eventTimestampUtc; }
    public String getPrevHash() { return prevHash; }
    public void setPrevHash(String prevHash) { this.prevHash = prevHash; }
    public String getCurrentHash() { return currentHash; }
    public void setCurrentHash(String currentHash) { this.currentHash = currentHash; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
