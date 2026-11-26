package com.trustguard.service;

import com.trustguard.audit.AuditLogService;
import com.trustguard.crypto.PostQuantumCryptoService;
import com.trustguard.crypto.ProtectedKeyStore;
import com.trustguard.dto.KeyVersionResponse;
import com.trustguard.entity.KeyVersionEntity;
import com.trustguard.entity.NodeKeyAcknowledgementEntity;
import com.trustguard.entity.ResourceEntity;
import com.trustguard.entity.SimulatedNodeEntity;
import com.trustguard.exception.AccessDeniedBusinessException;
import com.trustguard.exception.ConflictException;
import com.trustguard.exception.ResourceNotFoundException;
import com.trustguard.repository.KeyVersionRepository;
import com.trustguard.repository.NodeKeyAcknowledgementRepository;
import com.trustguard.repository.ResourceRepository;
import com.trustguard.repository.SimulatedNodeRepository;
import com.trustguard.security.SecurityUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class KeyManagementService {

    public static final String DEFAULT_ALIAS = "trustguard-data-key";

    private final KeyVersionRepository keyVersionRepository;
    private final SimulatedNodeRepository nodeRepository;
    private final NodeKeyAcknowledgementRepository ackRepository;
    private final ResourceRepository resourceRepository;
    private final PostQuantumCryptoService cryptoService;
    private final ProtectedKeyStore keyStore;
    private final AuditLogService auditLogService;
    private final SecurityPersistenceService persistenceService;
    private final int defaultGraceSeconds;

    public KeyManagementService(
            KeyVersionRepository keyVersionRepository,
            SimulatedNodeRepository nodeRepository,
            NodeKeyAcknowledgementRepository ackRepository,
            ResourceRepository resourceRepository,
            PostQuantumCryptoService cryptoService,
            ProtectedKeyStore keyStore,
            AuditLogService auditLogService,
            SecurityPersistenceService persistenceService,
            @Value("${trustguard.demo.default-grace-seconds:60}") int defaultGraceSeconds
    ) {
        this.keyVersionRepository = keyVersionRepository;
        this.nodeRepository = nodeRepository;
        this.ackRepository = ackRepository;
        this.resourceRepository = resourceRepository;
        this.cryptoService = cryptoService;
        this.keyStore = keyStore;
        this.auditLogService = auditLogService;
        this.persistenceService = persistenceService;
        this.defaultGraceSeconds = defaultGraceSeconds;
    }

    public static String sanitizeAlias(String alias) {
        String raw = (alias == null || alias.isBlank()) ? DEFAULT_ALIAS : alias.trim();
        return raw.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    public static String dekSecretId(String keyAlias, int versionNumber) {
        return "key-" + sanitizeAlias(keyAlias) + "-v" + versionNumber + "-dek";
    }

    public static String kemPrivSecretId(String keyAlias, int versionNumber) {
        return "key-" + sanitizeAlias(keyAlias) + "-v" + versionNumber + "-mlkem768-priv";
    }

    public byte[] loadDek(KeyVersionEntity keyVersion) {
        String scopedId = dekSecretId(keyVersion.getKeyAlias(), keyVersion.getVersionNumber());
        if (keyStore.contains(scopedId)) {
            return keyStore.loadSecret(scopedId);
        }
        if (DEFAULT_ALIAS.equals(keyVersion.getKeyAlias())) {
            String legacyId = "key-v" + keyVersion.getVersionNumber() + "-dek";
            if (keyStore.contains(legacyId)) {
                return keyStore.loadSecret(legacyId);
            }
        }
        throw new ResourceNotFoundException(
                "DEK missing in protected keystore for " + keyVersion.getKeyAlias() + ":v" + keyVersion.getVersionNumber()
        );
    }

    public List<KeyVersionResponse> listKeys() {
        return keyVersionRepository.findAllByOrderByVersionNumberDesc()
                .stream()
                .map(this::toDto)
                .toList();
    }

    public KeyVersionEntity getActiveCommittedKey() {
        return keyVersionRepository.findFirstByKeyAliasAndStatusOrderByVersionNumberDesc(DEFAULT_ALIAS, "COMMITTED")
                .or(() -> keyVersionRepository.findFirstByStatusOrderByVersionNumberDesc("COMMITTED"))
                .orElseThrow(() -> new ResourceNotFoundException("No committed active key version found"));
    }

    public KeyVersionEntity getActiveCommittedKey(String keyAlias) {
        String alias = (keyAlias == null || keyAlias.isBlank()) ? DEFAULT_ALIAS : keyAlias.trim();
        return keyVersionRepository.findFirstByKeyAliasAndStatusOrderByVersionNumberDesc(alias, "COMMITTED")
                .orElseGet(this::getActiveCommittedKey);
    }

    public Map<String, Object> getRotationStatus() {
        KeyVersionEntity active = getActiveCommittedKey();
        List<KeyVersionResponse> versions = listKeys();
        List<SimulatedNodeEntity> nodes = nodeRepository.findAllByOrderByIdAsc();
        long ackedOnLatest = 0;
        if (!versions.isEmpty()) {
            KeyVersionResponse latest = versions.get(0);
            ackedOnLatest = latest.acknowledgements().stream()
                    .filter(a -> "ACKNOWLEDGED".equals(a.ackStatus()))
                    .count();
        }
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("activeVersion", active.getVersionNumber());
        status.put("activeAlias", active.getKeyAlias());
        status.put("activeAlgorithm", active.getAlgorithm());
        status.put("activeSince", active.getActivationTime());
        status.put("totalNodes", nodes.size());
        status.put("acknowledgedNodesOnLatest", ackedOnLatest);
        status.put("versions", versions);
        status.put("nodes", nodes);
        return status;
    }

    @Transactional
    public KeyVersionResponse prepareKey(String requestedAlias, Integer gracePeriodSeconds) {
        String alias = (requestedAlias == null || requestedAlias.isBlank()) ? DEFAULT_ALIAS : requestedAlias.trim();
        int grace = gracePeriodSeconds != null ? gracePeriodSeconds : defaultGraceSeconds;

        int nextVersion = keyVersionRepository.findFirstByKeyAliasOrderByVersionNumberDesc(alias)
                .map(k -> k.getVersionNumber() + 1)
                .orElse(1);

        PostQuantumCryptoService.RawKeyPair kemPair = cryptoService.generateMlKem768KeyPair();
        byte[] dek = cryptoService.generateRandomAes256Key();
        String kemPrivRef = keyStore.storeSecret(kemPrivSecretId(alias, nextVersion), kemPair.privateKey());
        keyStore.storeSecret(dekSecretId(alias, nextVersion), dek);
        cryptoService.zeroize(kemPair.privateKey(), dek);

        Instant now = Instant.now();
        KeyVersionEntity key = new KeyVersionEntity();
        key.setKeyAlias(alias);
        key.setVersionNumber(nextVersion);
        key.setAlgorithm("ML-KEM-768 + AES-256-GCM");
        key.setStatus("PREPARED");
        key.setPublicKeyB64(Base64.getEncoder().encodeToString(kemPair.publicKey()));
        key.setPublicKeyFingerprint(kemPair.fingerprintSha256());
        key.setKeyReference(kemPrivRef);
        key.setGracePeriodSeconds(grace);
        key.setCreatedAt(now);
        key = keyVersionRepository.save(key);

        // Transition PREPARED -> DISTRIBUTED across simulated nodes with PENDING acknowledgements
        List<SimulatedNodeEntity> nodes = nodeRepository.findAllByOrderByIdAsc();
        key.setStatus("DISTRIBUTED");
        key.setDistributedAt(Instant.now());
        key = keyVersionRepository.save(key);

        for (SimulatedNodeEntity node : nodes) {
            NodeKeyAcknowledgementEntity ack = new NodeKeyAcknowledgementEntity();
            ack.setKeyVersion(key);
            ack.setNode(node);
            ack.setAckStatus("PENDING");
            ack.setDetailMessage("Key " + alias + " v" + nextVersion + " distributed; awaiting node verification");
            ackRepository.save(ack);
        }

        String actor = currentActorOrSystem();
        auditLogService.appendEvent(
                actor,
                "KEY_PREPARED_AND_DISTRIBUTED",
                alias + ":v" + nextVersion,
                "Prepared ML-KEM-768 key " + alias + ":v" + nextVersion + " (grace=" + grace + "s) and distributed to " + nodes.size() + " nodes"
        );
        return toDto(key);
    }

    @Transactional
    public KeyVersionResponse acknowledgeKey(Long keyId, String nodeCode) {
        KeyVersionEntity key = keyVersionRepository.findById(keyId)
                .orElseThrow(() -> new ResourceNotFoundException("Key version not found: " + keyId));
        if ("COMMITTED".equals(key.getStatus()) || "RETIRED".equals(key.getStatus())) {
            throw new ConflictException("INVALID_KEY_STATE", "Key v" + key.getVersionNumber() + " is already " + key.getStatus());
        }

        List<NodeKeyAcknowledgementEntity> acks = ackRepository.findByKeyVersionIdOrderByNodeIdAsc(keyId);
        if (acks.isEmpty()) {
            throw new ConflictException("NO_NODES", "No simulated nodes configured for key acknowledgement");
        }

        boolean anyFailed = false;
        StringBuilder failures = new StringBuilder();
        for (NodeKeyAcknowledgementEntity ack : acks) {
            SimulatedNodeEntity node = ack.getNode();
            if (nodeCode != null && !nodeCode.isBlank() && !node.getNodeCode().equals(nodeCode)) {
                continue;
            }
            if (node.isSimulateAckFailure() || "OFFLINE".equalsIgnoreCase(node.getStatus())) {
                ack.setAckStatus("FAILED");
                ack.setAcknowledgedAt(Instant.now());
                ack.setDetailMessage("Node " + node.getNodeCode() + " failed acknowledgement check (simulated outage/mismatch)");
                anyFailed = true;
                failures.append(node.getNodeCode()).append(" ");
            } else {
                ack.setAckStatus("ACKNOWLEDGED");
                ack.setAcknowledgedAt(Instant.now());
                ack.setDetailMessage("Node " + node.getNodeCode() + " verified fingerprint "
                        + key.getPublicKeyFingerprint().substring(0, 12));
            }
            ackRepository.save(ack);
        }

        List<NodeKeyAcknowledgementEntity> refreshed = ackRepository.findByKeyVersionIdOrderByNodeIdAsc(keyId);
        boolean allAcked = refreshed.stream().allMatch(a -> "ACKNOWLEDGED".equals(a.getAckStatus()));
        boolean hasFailure = refreshed.stream().anyMatch(a -> "FAILED".equals(a.getAckStatus()));

        if (allAcked) {
            key.setStatus("ACKNOWLEDGED");
            key.setFailureReason(null);
        } else if (hasFailure || anyFailed) {
            key.setStatus("DISTRIBUTED");
            key.setFailureReason("Pending/failed acknowledgement on node(s): " + failures.toString().trim());
        }
        keyVersionRepository.save(key);

        auditLogService.appendEvent(
                currentActorOrSystem(),
                allAcked ? "KEY_ACKNOWLEDGED_ALL_NODES" : "KEY_ACK_INCOMPLETE",
                key.getKeyAlias() + ":v" + key.getVersionNumber(),
                allAcked
                        ? "All " + refreshed.size() + " simulated nodes acknowledged v" + key.getVersionNumber()
                        : "Acknowledgement incomplete or failed: " + key.getFailureReason()
        );
        return toDto(key);
    }

    public KeyVersionResponse commitKey(Long keyId) {
        KeyVersionEntity candidateCheck = keyVersionRepository.findById(keyId)
                .orElseThrow(() -> new ResourceNotFoundException("Key version not found: " + keyId));
        if ("COMMITTED".equals(candidateCheck.getStatus())) {
            throw new ConflictException("ALREADY_COMMITTED", "Key version is already committed");
        }
        if ("RETIRED".equals(candidateCheck.getStatus())) {
            throw new ConflictException("KEY_RETIRED", "Cannot commit a retired key version");
        }

        List<NodeKeyAcknowledgementEntity> acks = ackRepository.findByKeyVersionIdOrderByNodeIdAsc(keyId);
        List<String> unacked = acks.stream()
                .filter(a -> !"ACKNOWLEDGED".equals(a.getAckStatus()))
                .map(a -> a.getNode().getNodeCode() + "(" + a.getAckStatus() + ")")
                .toList();

        if (acks.isEmpty() || !unacked.isEmpty()) {
            String msg = "Commit blocked: required simulated nodes have not acknowledged v"
                    + candidateCheck.getVersionNumber() + ": " + String.join(", ", unacked);
            String actor = currentActorOrSystem();
            persistenceService.runInRequiresNew(() -> {
                KeyVersionEntity rejected = keyVersionRepository.findById(keyId).orElse(null);
                if (rejected != null) {
                    rejected.setFailureReason(msg.length() <= 255 ? msg : msg.substring(0, 255));
                    keyVersionRepository.save(rejected);
                }
            });
            auditLogService.appendEvent(
                    actor,
                    "KEY_COMMIT_REJECTED",
                    candidateCheck.getKeyAlias() + ":v" + candidateCheck.getVersionNumber(),
                    msg
            );
            throw new ConflictException("ACK_QUORUM_NOT_MET", msg);
        }

        return persistenceService.inTransaction(() -> {
            KeyVersionEntity candidate = keyVersionRepository.findById(keyId)
                    .orElseThrow(() -> new ResourceNotFoundException("Key version not found: " + keyId));
            Instant now = Instant.now();
            KeyVersionEntity previousActive = keyVersionRepository
                    .findFirstByKeyAliasAndStatusOrderByVersionNumberDesc(candidate.getKeyAlias(), "COMMITTED")
                    .orElse(null);

            if (previousActive != null && !previousActive.getId().equals(candidate.getId())) {
                int grace = candidate.getGracePeriodSeconds();
                Instant cutoff = grace > 0 ? now.plusSeconds(grace) : now;
                previousActive.setStatus("RETIRED");
                previousActive.setGraceUntil(cutoff);
                previousActive.setCutoffTime(cutoff);
                keyVersionRepository.save(previousActive);
            }

            candidate.setStatus("COMMITTED");
            candidate.setCommittedAt(now);
            candidate.setActivationTime(now);
            candidate.setFailureReason(null);
            candidate = keyVersionRepository.save(candidate);

            List<SimulatedNodeEntity> nodes = nodeRepository.findAllByOrderByIdAsc();
            if (DEFAULT_ALIAS.equals(candidate.getKeyAlias())) {
                for (SimulatedNodeEntity node : nodes) {
                    node.setCurrentKeyVersion(candidate.getVersionNumber());
                    node.setLastHeartbeatAt(now);
                    nodeRepository.save(node);
                }
            }

            // Re-wrap protected resource payloads under the newly committed DEK for this alias
            if (previousActive != null) {
                byte[] oldDek = loadDek(previousActive);
                byte[] newDek = loadDek(candidate);
                try {
                    for (ResourceEntity res : resourceRepository.findAll()) {
                        if (res.getActiveKeyVersion().getId().equals(previousActive.getId())) {
                            String plaintext = cryptoService.decryptAes256Gcm(
                                    oldDek,
                                    res.getContentIvB64(),
                                    res.getContentCiphertextB64(),
                                    res.getContentAad()
                            );
                            PostQuantumCryptoService.AesGcmPayload rewrapped = cryptoService.encryptAes256Gcm(
                                    newDek,
                                    plaintext,
                                    res.getContentAad()
                            );
                            res.setContentIvB64(rewrapped.ivB64());
                            res.setContentCiphertextB64(rewrapped.ciphertextB64());
                            res.setActiveKeyVersion(candidate);
                            res.setUpdatedAt(now);
                            resourceRepository.save(res);
                        }
                    }
                } finally {
                    cryptoService.zeroize(oldDek, newDek);
                }
            }

            auditLogService.appendEvent(
                    currentActorOrSystem(),
                    "KEY_COMMITTED",
                    candidate.getKeyAlias() + ":v" + candidate.getVersionNumber(),
                    "Committed key " + candidate.getKeyAlias() + ":v" + candidate.getVersionNumber()
                            + " across " + nodes.size() + " nodes; "
                            + (previousActive != null ? "v" + previousActive.getVersionNumber() + " cutoff at " + previousActive.getCutoffTime() : "initial commit")
            );

            return toDto(candidate);
        });
    }

    public KeyVersionEntity validateKeyUsage(Integer requestedVersion, Instant evaluationTime) {
        return validateKeyUsage(DEFAULT_ALIAS, requestedVersion, evaluationTime);
    }

    public KeyVersionEntity validateKeyUsage(String keyAlias, Integer requestedVersion, Instant evaluationTime) {
        String alias = (keyAlias == null || keyAlias.isBlank()) ? DEFAULT_ALIAS : keyAlias.trim();
        KeyVersionEntity active = getActiveCommittedKey(alias);
        if (requestedVersion == null || (requestedVersion == active.getVersionNumber() && alias.equals(active.getKeyAlias()))) {
            return active;
        }
        KeyVersionEntity requested = keyVersionRepository.findByKeyAliasAndVersionNumber(alias, requestedVersion)
                .orElseThrow(() -> new AccessDeniedBusinessException(
                        "UNKNOWN_KEY_VERSION",
                        "Requested key version " + alias + ":v" + requestedVersion + " does not exist"
                ));
        if ("PREPARED".equals(requested.getStatus()) || "DISTRIBUTED".equals(requested.getStatus())
                || "ACKNOWLEDGED".equals(requested.getStatus())) {
            throw new AccessDeniedBusinessException(
                    "UNCOMMITTED_KEY_VERSION",
                    "Key version " + alias + ":v" + requestedVersion + " is not yet committed for operational use"
            );
        }
        if ("RETIRED".equals(requested.getStatus())) {
            Instant cutoff = requested.getCutoffTime();
            if (cutoff == null || !evaluationTime.isBefore(cutoff)) {
                throw new AccessDeniedBusinessException(
                        "KEY_PAST_CUTOFF",
                        "Key version " + alias + ":v" + requestedVersion + " is retired and rejected after cutoff " + cutoff
                );
            }
        }
        return requested;
    }

    public KeyVersionResponse toDto(KeyVersionEntity entity) {
        List<KeyVersionResponse.NodeAckDto> acks = ackRepository.findByKeyVersionIdOrderByNodeIdAsc(entity.getId())
                .stream()
                .map(a -> new KeyVersionResponse.NodeAckDto(
                        a.getNode().getNodeCode(),
                        a.getNode().getNodeName(),
                        a.getAckStatus(),
                        a.getAcknowledgedAt(),
                        a.getDetailMessage()
                ))
                .toList();
        return new KeyVersionResponse(
                entity.getId(),
                entity.getKeyAlias(),
                entity.getVersionNumber(),
                entity.getAlgorithm(),
                entity.getStatus(),
                entity.getPublicKeyFingerprint(),
                entity.getGracePeriodSeconds(),
                entity.getCreatedAt(),
                entity.getDistributedAt(),
                entity.getCommittedAt(),
                entity.getActivationTime(),
                entity.getGraceUntil(),
                entity.getCutoffTime(),
                entity.getFailureReason(),
                acks
        );
    }

    private String currentActorOrSystem() {
        try {
            return SecurityUtils.currentUsername();
        } catch (Exception e) {
            return "system";
        }
    }
}
