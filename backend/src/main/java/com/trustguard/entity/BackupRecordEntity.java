package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "backup_records")
public class BackupRecordEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "backup_id", nullable = false, unique = true, length = 80)
    private String backupId;

    @Column(name = "created_by", nullable = false, length = 64)
    private String createdBy;

    @Column(name = "key_version_number", nullable = false)
    private int keyVersionNumber;

    @Column(name = "revocation_version", nullable = false)
    private long revocationVersion;

    @Column(name = "checksum_sha256", nullable = false, length = 64)
    private String checksumSha256;

    @Column(name = "verification_status", nullable = false, length = 32)
    private String verificationStatus;

    @Column(name = "restore_status", nullable = false, length = 32)
    private String restoreStatus;

    @Column(name = "item_count", nullable = false)
    private int itemCount;

    @Lob
    @Column(name = "payload_snapshot_json", nullable = false, columnDefinition = "LONGTEXT")
    private String payloadSnapshotJson;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @Column(name = "restored_at")
    private Instant restoredAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getBackupId() { return backupId; }
    public void setBackupId(String backupId) { this.backupId = backupId; }
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    public int getKeyVersionNumber() { return keyVersionNumber; }
    public void setKeyVersionNumber(int keyVersionNumber) { this.keyVersionNumber = keyVersionNumber; }
    public long getRevocationVersion() { return revocationVersion; }
    public void setRevocationVersion(long revocationVersion) { this.revocationVersion = revocationVersion; }
    public String getChecksumSha256() { return checksumSha256; }
    public void setChecksumSha256(String checksumSha256) { this.checksumSha256 = checksumSha256; }
    public String getVerificationStatus() { return verificationStatus; }
    public void setVerificationStatus(String verificationStatus) { this.verificationStatus = verificationStatus; }
    public String getRestoreStatus() { return restoreStatus; }
    public void setRestoreStatus(String restoreStatus) { this.restoreStatus = restoreStatus; }
    public int getItemCount() { return itemCount; }
    public void setItemCount(int itemCount) { this.itemCount = itemCount; }
    public String getPayloadSnapshotJson() { return payloadSnapshotJson; }
    public void setPayloadSnapshotJson(String payloadSnapshotJson) { this.payloadSnapshotJson = payloadSnapshotJson; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getVerifiedAt() { return verifiedAt; }
    public void setVerifiedAt(Instant verifiedAt) { this.verifiedAt = verifiedAt; }
    public Instant getRestoredAt() { return restoredAt; }
    public void setRestoredAt(Instant restoredAt) { this.restoredAt = restoredAt; }
}
