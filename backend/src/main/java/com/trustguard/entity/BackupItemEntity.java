package com.trustguard.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "backup_items")
public class BackupItemEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "backup_record_id", nullable = false)
    private BackupRecordEntity backupRecord;

    @Column(name = "item_type", nullable = false, length = 40)
    private String itemType;

    @Column(name = "item_key", nullable = false, length = 96)
    private String itemKey;

    @Column(name = "item_checksum_sha256", nullable = false, length = 64)
    private String itemChecksumSha256;

    @Column(name = "serialized_data_json", nullable = false, columnDefinition = "TEXT")
    private String serializedDataJson;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public BackupRecordEntity getBackupRecord() { return backupRecord; }
    public void setBackupRecord(BackupRecordEntity backupRecord) { this.backupRecord = backupRecord; }
    public String getItemType() { return itemType; }
    public void setItemType(String itemType) { this.itemType = itemType; }
    public String getItemKey() { return itemKey; }
    public void setItemKey(String itemKey) { this.itemKey = itemKey; }
    public String getItemChecksumSha256() { return itemChecksumSha256; }
    public void setItemChecksumSha256(String itemChecksumSha256) { this.itemChecksumSha256 = itemChecksumSha256; }
    public String getSerializedDataJson() { return serializedDataJson; }
    public void setSerializedDataJson(String serializedDataJson) { this.serializedDataJson = serializedDataJson; }
}
