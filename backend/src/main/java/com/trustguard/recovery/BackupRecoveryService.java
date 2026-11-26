package com.trustguard.recovery;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.audit.AuditLogService;
import com.trustguard.crypto.PostQuantumCryptoService;
import com.trustguard.crypto.ProtectedKeyStore;
import com.trustguard.dto.BackupResponse;
import com.trustguard.entity.BackupItemEntity;
import com.trustguard.entity.BackupRecordEntity;
import com.trustguard.entity.KeyVersionEntity;
import com.trustguard.entity.ResourceEntity;
import com.trustguard.entity.RevocationEntity;
import com.trustguard.entity.SimulatedNodeEntity;
import com.trustguard.entity.UserEntity;
import com.trustguard.exception.IntegrityViolationException;
import com.trustguard.exception.ResourceNotFoundException;
import com.trustguard.repository.BackupItemRepository;
import com.trustguard.repository.BackupRecordRepository;
import com.trustguard.repository.DeviceRepository;
import com.trustguard.repository.KeyVersionRepository;
import com.trustguard.repository.ResourceRepository;
import com.trustguard.repository.RevocationRepository;
import com.trustguard.repository.SimulatedNodeRepository;
import com.trustguard.repository.UserRepository;
import com.trustguard.security.SecurityUtils;
import com.trustguard.service.KeyManagementService;
import com.trustguard.service.SecurityPersistenceService;
import com.trustguard.util.CanonicalJsonUtil;
import com.trustguard.util.HashUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class BackupRecoveryService {

    private final BackupRecordRepository backupRecordRepository;
    private final BackupItemRepository backupItemRepository;
    private final DeviceRepository deviceRepository;
    private final KeyVersionRepository keyVersionRepository;
    private final RevocationRepository revocationRepository;
    private final ResourceRepository resourceRepository;
    private final SimulatedNodeRepository nodeRepository;
    private final UserRepository userRepository;
    private final KeyManagementService keyManagementService;
    private final PostQuantumCryptoService cryptoService;
    private final ProtectedKeyStore keyStore;
    private final AuditLogService auditLogService;
    private final SecurityPersistenceService persistenceService;
    private final ObjectMapper objectMapper;

    public BackupRecoveryService(
            BackupRecordRepository backupRecordRepository,
            BackupItemRepository backupItemRepository,
            DeviceRepository deviceRepository,
            KeyVersionRepository keyVersionRepository,
            RevocationRepository revocationRepository,
            ResourceRepository resourceRepository,
            SimulatedNodeRepository nodeRepository,
            UserRepository userRepository,
            KeyManagementService keyManagementService,
            PostQuantumCryptoService cryptoService,
            ProtectedKeyStore keyStore,
            AuditLogService auditLogService,
            SecurityPersistenceService persistenceService,
            ObjectMapper objectMapper
    ) {
        this.backupRecordRepository = backupRecordRepository;
        this.backupItemRepository = backupItemRepository;
        this.deviceRepository = deviceRepository;
        this.keyVersionRepository = keyVersionRepository;
        this.revocationRepository = revocationRepository;
        this.resourceRepository = resourceRepository;
        this.nodeRepository = nodeRepository;
        this.userRepository = userRepository;
        this.keyManagementService = keyManagementService;
        this.cryptoService = cryptoService;
        this.keyStore = keyStore;
        this.auditLogService = auditLogService;
        this.persistenceService = persistenceService;
        this.objectMapper = objectMapper;
    }

    public List<BackupResponse> listBackups() {
        return backupRecordRepository.findAllByOrderByCreatedAtDesc().stream()
                .map(b -> toDto(b, "HMAC-SHA-256 + SHA-256 snapshot"))
                .toList();
    }

    @Transactional
    public BackupResponse createBackup() {
        String actor = SecurityUtils.currentUsername();
        String backupId = "bak-" + UUID.randomUUID().toString().substring(0, 10);
        Instant now = Instant.now();

        KeyVersionEntity activeKey = keyManagementService.getActiveCommittedKey();
        long latestRevocationVersion = revocationRepository.findTopByOrderByRevocationVersionDesc()
                .map(RevocationEntity::getRevocationVersion)
                .orElse(0L);

        List<Map<String, Object>> deviceSnapshots = deviceRepository.findAllByOrderByEnrolledAtDesc().stream()
                .map(d -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("deviceUid", d.getDeviceUid());
                    m.put("ownerUsername", d.getOwner().getUsername());
                    m.put("status", d.getStatus());
                    m.put("revokedAt", d.getRevokedAt() != null ? d.getRevokedAt().toString() : null);
                    m.put("publicKeyFingerprint", d.getPublicKeyFingerprint());
                    return m;
                })
                .toList();

        List<Map<String, Object>> resourceSnapshots = resourceRepository.findAllByOrderByIdAsc().stream()
                .map(r -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("resourceKey", r.getResourceKey());
                    m.put("title", r.getTitle());
                    m.put("ownerUsername", r.getOwner().getUsername());
                    m.put("allowedServices", r.getAllowedServices());
                    m.put("classification", r.getClassification());
                    m.put("keyAlias", r.getActiveKeyVersion().getKeyAlias());
                    m.put("activeKeyVersion", r.getActiveKeyVersion().getVersionNumber());
                    m.put("contentCiphertextB64", r.getContentCiphertextB64());
                    m.put("contentIvB64", r.getContentIvB64());
                    m.put("contentAad", r.getContentAad());
                    return m;
                })
                .toList();

        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("backupId", backupId);
        snapshot.put("committedKeyVersion", activeKey.getVersionNumber());
        snapshot.put("revocationVersion", latestRevocationVersion);
        snapshot.put("devices", deviceSnapshots);
        snapshot.put("resources", resourceSnapshots);
        snapshot.put("createdAt", now.toString());

        String canonicalSnapshot = CanonicalJsonUtil.toCanonicalJson(snapshot);
        String checksum = HashUtil.sha256Hex(canonicalSnapshot);

        BackupRecordEntity record = new BackupRecordEntity();
        record.setBackupId(backupId);
        record.setCreatedBy(actor);
        record.setKeyVersionNumber(activeKey.getVersionNumber());
        record.setRevocationVersion(latestRevocationVersion);
        record.setChecksumSha256(checksum);
        record.setVerificationStatus("VERIFIED");
        record.setRestoreStatus("NOT_RESTORED");
        record.setItemCount(deviceSnapshots.size() + resourceSnapshots.size());
        record.setPayloadSnapshotJson(canonicalSnapshot);
        record.setCreatedAt(now);
        record.setVerifiedAt(now);
        record.setHmacSha256(computeBackupHmac(record, checksum, canonicalSnapshot));
        record = backupRecordRepository.save(record);

        List<BackupItemEntity> items = new ArrayList<>();
        for (Map<String, Object> d : deviceSnapshots) {
            String json = CanonicalJsonUtil.toCanonicalJson(d);
            BackupItemEntity item = new BackupItemEntity();
            item.setBackupRecord(record);
            item.setItemType("DEVICE_STATE");
            item.setItemKey(String.valueOf(d.get("deviceUid")));
            item.setItemChecksumSha256(HashUtil.sha256Hex(json));
            item.setSerializedDataJson(json);
            items.add(item);
        }
        for (Map<String, Object> r : resourceSnapshots) {
            String json = CanonicalJsonUtil.toCanonicalJson(r);
            BackupItemEntity item = new BackupItemEntity();
            item.setBackupRecord(record);
            item.setItemType("RESOURCE_CIPHERTEXT");
            item.setItemKey(String.valueOf(r.get("resourceKey")));
            item.setItemChecksumSha256(HashUtil.sha256Hex(json));
            item.setSerializedDataJson(json);
            items.add(item);
        }
        backupItemRepository.saveAll(items);

        auditLogService.appendEvent(
                actor,
                "BACKUP_CREATED",
                backupId,
                "Created HMAC-SHA-256 verified backup (key v" + activeKey.getVersionNumber()
                        + ", revocation v" + latestRevocationVersion + ", sha256=" + checksum.substring(0, 12) + ")"
        );
        return toDto(record, "Created and HMAC-verified SHA-256 backup snapshot");
    }

    private BackupRecordEntity resolveBackup(String identifier) {
        if (identifier != null && identifier.matches("\\d+")) {
            return backupRecordRepository.findById(Long.parseLong(identifier))
                    .orElseThrow(() -> new ResourceNotFoundException("Backup not found: " + identifier));
        }
        return backupRecordRepository.findByBackupId(identifier)
                .orElseThrow(() -> new ResourceNotFoundException("Backup not found: " + identifier));
    }

    @Transactional
    public BackupResponse verifyBackup(String identifier) {
        BackupRecordEntity record = resolveBackup(identifier);
        String actualChecksum = HashUtil.sha256Hex(record.getPayloadSnapshotJson());
        boolean valid = verifyBackupIntegrity(record, actualChecksum);

        record.setVerificationStatus(valid ? "VERIFIED" : "CORRUPTED");
        record.setVerifiedAt(Instant.now());
        backupRecordRepository.save(record);

        auditLogService.appendEvent(
                SecurityUtils.currentUsername(),
                valid ? "BACKUP_VERIFIED" : "BACKUP_VERIFICATION_FAILED",
                record.getBackupId(),
                valid
                        ? "Backup HMAC + SHA-256 integrity verified: " + actualChecksum.substring(0, 12)
                        : "CORRUPTED backup detected! Failed SHA-256 or HMAC authentication"
        );
        return toDto(record, valid ? "Backup HMAC & checksum verified" : "Backup integrity mismatch: CORRUPTED");
    }

    @Transactional
    public BackupResponse simulateCorruption(String identifier) {
        BackupRecordEntity record = resolveBackup(identifier);
        record.setPayloadSnapshotJson(record.getPayloadSnapshotJson() + " ");
        record.setVerificationStatus("CORRUPTED");
        backupRecordRepository.save(record);
        auditLogService.appendEvent(
                SecurityUtils.currentUsername(),
                "BACKUP_CORRUPTION_SIMULATED",
                record.getBackupId(),
                "Simulated snapshot payload alteration to demonstrate HMAC/checksum verification rejection"
        );
        return toDto(record, "Simulated payload corruption applied (checksum no longer matches)");
    }

    public BackupResponse restoreBackup(String identifier) {
        String actor = SecurityUtils.currentUsername();
        BackupRecordEntity probe = resolveBackup(identifier);
        String actualChecksum = HashUtil.sha256Hex(probe.getPayloadSnapshotJson());

        if (!verifyBackupIntegrity(probe, actualChecksum)) {
            persistenceService.runInRequiresNew(() -> {
                BackupRecordEntity failed = resolveBackup(identifier);
                failed.setVerificationStatus("CORRUPTED");
                failed.setRestoreStatus("REJECTED");
                failed.setVerifiedAt(Instant.now());
                backupRecordRepository.save(failed);
            });
            auditLogService.appendEvent(
                    actor,
                    "BACKUP_RESTORE_REJECTED",
                    probe.getBackupId(),
                    "Rejected restore of corrupted/forged backup " + probe.getBackupId() + " due to HMAC/SHA-256 mismatch"
            );
            throw new IntegrityViolationException(
                    "BACKUP_CORRUPTED",
                    "Restore rejected: backup " + probe.getBackupId() + " failed HMAC/SHA-256 integrity verification"
            );
        }

        // Parse verified snapshot and apply restore atomically while preserving higher committed keys & revocations
        Map<String, Object> snapshot;
        try {
            snapshot = objectMapper.readValue(probe.getPayloadSnapshotJson(), new TypeReference<>() {});
        } catch (Exception e) {
            throw new IntegrityViolationException("BACKUP_PARSE_ERROR", "Verified backup JSON could not be parsed");
        }

        return persistenceService.inTransaction(() -> {
            BackupRecordEntity record = resolveBackup(identifier);
            Instant now = Instant.now();

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> snapDevices = (List<Map<String, Object>>) snapshot.get("devices");
            if (snapDevices != null) {
                for (Map<String, Object> sd : snapDevices) {
                    String deviceUid = String.valueOf(sd.get("deviceUid"));
                    String snapStatus = String.valueOf(sd.get("status"));
                    deviceRepository.findByDeviceUid(deviceUid).ifPresent(device -> {
                        // Never un-revoke a device that has been revoked after the backup was taken!
                        if ("REVOKED".equals(snapStatus) && !"REVOKED".equals(device.getStatus())) {
                            device.setStatus("REVOKED");
                            device.setRevokedAt(now);
                            deviceRepository.save(device);
                        }
                    });
                }
            }

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> snapResources = (List<Map<String, Object>>) snapshot.get("resources");
            if (snapResources != null) {
                for (Map<String, Object> sr : snapResources) {
                    restoreResourceSnapshot(sr, record.getKeyVersionNumber(), now);
                }
            }

            // Ensure simulated nodes keep at least the latest revocation version & active key version
            int currentActiveKeyVersion = keyManagementService.getActiveCommittedKey().getVersionNumber();
            long currentRevocationVersion = revocationRepository.findTopByOrderByRevocationVersionDesc()
                    .map(RevocationEntity::getRevocationVersion)
                    .orElse(record.getRevocationVersion());

            for (SimulatedNodeEntity node : nodeRepository.findAllByOrderByIdAsc()) {
                node.setCurrentKeyVersion(Math.max(node.getCurrentKeyVersion(), currentActiveKeyVersion));
                node.setCurrentRevocationVersion(Math.max(node.getCurrentRevocationVersion(), currentRevocationVersion));
                node.setLastHeartbeatAt(now);
                nodeRepository.save(node);
            }

            record.setVerificationStatus("VERIFIED");
            record.setRestoreStatus("RESTORED");
            record.setVerifiedAt(now);
            record.setRestoredAt(now);
            backupRecordRepository.save(record);

            auditLogService.appendEvent(
                    actor,
                    "BACKUP_RESTORED",
                    record.getBackupId(),
                    "Restored verified backup " + record.getBackupId()
                            + " (devices + resources) while preserving committed key v"
                            + currentActiveKeyVersion + " and revocation v" + currentRevocationVersion
            );

            return toDto(record, "Restored verified backup; committed key v" + currentActiveKeyVersion
                    + " and revocation state v" + currentRevocationVersion + " retained");
        });
    }

    private void restoreResourceSnapshot(Map<String, Object> sr, int fallbackKeyVer, Instant now) {
        String resourceKey = sr.get("resourceKey") != null ? String.valueOf(sr.get("resourceKey")) : null;
        String snapCt = sr.get("contentCiphertextB64") != null ? String.valueOf(sr.get("contentCiphertextB64")) : null;
        String snapIv = sr.get("contentIvB64") != null ? String.valueOf(sr.get("contentIvB64")) : null;
        String snapAad = sr.get("contentAad") != null ? String.valueOf(sr.get("contentAad")) : null;
        if (resourceKey == null || snapCt == null || snapIv == null || snapAad == null) {
            return;
        }

        String snapAlias = sr.get("keyAlias") != null
                ? String.valueOf(sr.get("keyAlias"))
                : KeyManagementService.DEFAULT_ALIAS;
        int snapKeyVerNum = (sr.get("activeKeyVersion") instanceof Number n) ? n.intValue() : fallbackKeyVer;

        KeyVersionEntity currentCommittedForAlias = keyManagementService.getActiveCommittedKey(snapAlias);
        KeyVersionEntity snapKeyEntity = keyVersionRepository
                .findByKeyAliasAndVersionNumber(snapAlias, snapKeyVerNum)
                .orElse(currentCommittedForAlias);

        ResourceEntity existing = resourceRepository.findByResourceKey(resourceKey).orElse(null);
        KeyVersionEntity targetKey = currentCommittedForAlias;
        if (existing != null && existing.getActiveKeyVersion() != null
                && existing.getActiveKeyVersion().getVersionNumber() > targetKey.getVersionNumber()
                && snapAlias.equals(existing.getActiveKeyVersion().getKeyAlias())) {
            targetKey = existing.getActiveKeyVersion();
        }
        if (targetKey.getVersionNumber() < snapKeyEntity.getVersionNumber()) {
            targetKey = snapKeyEntity;
        }

        String finalCt = snapCt;
        String finalIv = snapIv;
        if (!targetKey.getId().equals(snapKeyEntity.getId())) {
            byte[] oldDek = keyManagementService.loadDek(snapKeyEntity);
            byte[] newDek = keyManagementService.loadDek(targetKey);
            try {
                String plaintext = cryptoService.decryptAes256Gcm(oldDek, snapIv, snapCt, snapAad);
                PostQuantumCryptoService.AesGcmPayload rewrapped = cryptoService.encryptAes256Gcm(newDek, plaintext, snapAad);
                finalCt = rewrapped.ciphertextB64();
                finalIv = rewrapped.ivB64();
            } finally {
                cryptoService.zeroize(oldDek, newDek);
            }
        }

        ResourceEntity entity = existing;
        if (entity == null) {
            String ownerUsername = sr.get("ownerUsername") != null ? String.valueOf(sr.get("ownerUsername")) : null;
            if (ownerUsername == null) {
                return;
            }
            UserEntity owner = userRepository.findByUsername(ownerUsername).orElse(null);
            if (owner == null) {
                return;
            }
            entity = new ResourceEntity();
            entity.setResourceKey(resourceKey);
            entity.setOwner(owner);
            entity.setCreatedAt(now);
        }

        if (sr.get("title") != null) {
            entity.setTitle(String.valueOf(sr.get("title")));
        }
        if (sr.get("allowedServices") != null) {
            entity.setAllowedServices(String.valueOf(sr.get("allowedServices")));
        }
        if (sr.get("classification") != null) {
            entity.setClassification(String.valueOf(sr.get("classification")));
        }
        entity.setContentCiphertextB64(finalCt);
        entity.setContentIvB64(finalIv);
        entity.setContentAad(snapAad);
        entity.setActiveKeyVersion(targetKey);
        entity.setUpdatedAt(now);
        resourceRepository.save(entity);
    }

    private boolean verifyBackupIntegrity(BackupRecordEntity record, String actualChecksum) {
        if (!HashUtil.constantTimeEquals(record.getChecksumSha256(), actualChecksum)) {
            return false;
        }
        if (record.getHmacSha256() == null || record.getHmacSha256().isBlank()) {
            return false;
        }
        String expectedHmac = computeBackupHmac(record, actualChecksum, record.getPayloadSnapshotJson());
        return HashUtil.constantTimeEquals(record.getHmacSha256(), expectedHmac);
    }

    private String computeBackupHmac(BackupRecordEntity record, String checksumSha256, String payloadSnapshotJson) {
        byte[] hmacKey = keyStore.getOrCreateBackupHmacKey();
        try {
            String binding = record.getBackupId()
                    + "|" + record.getKeyVersionNumber()
                    + "|" + record.getRevocationVersion()
                    + "|" + checksumSha256
                    + "|" + payloadSnapshotJson;
            return HashUtil.hmacSha256Hex(hmacKey, binding.getBytes(StandardCharsets.UTF_8));
        } finally {
            cryptoService.zeroize(hmacKey);
        }
    }

    private BackupResponse toDto(BackupRecordEntity b, String message) {
        return new BackupResponse(
                b.getBackupId(),
                b.getCreatedBy(),
                b.getKeyVersionNumber(),
                b.getRevocationVersion(),
                b.getChecksumSha256(),
                b.getVerificationStatus(),
                b.getRestoreStatus(),
                b.getItemCount(),
                b.getCreatedAt(),
                b.getVerifiedAt(),
                b.getRestoredAt(),
                message
        );
    }
}
