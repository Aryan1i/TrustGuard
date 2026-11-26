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
    private final int defaultGraceSeconds;

    public KeyManagementService(
            KeyVersionRepository keyVersionRepository,
            SimulatedNodeRepository nodeRepository,
            NodeKeyAcknowledgementRepository ackRepository,
            ResourceRepository resourceRepository,
            PostQuantumCryptoService cryptoService,
            ProtectedKeyStore keyStore,
            AuditLogService auditLogService,
            @Value("${trustguard.demo.default-grace-seconds:60}") int defaultGraceSeconds
    ) {
        this.keyVersionRepository = keyVersionRepository;
        this.nodeRepository = nodeRepository;
        this.ackRepository = ackRepository;
        this.resourceRepository = resourceRepository;
        this.cryptoService = cryptoService;
        this.keyStore = keyStore;
        this.auditLogService = auditLogService;
        this.defaultGraceSeconds = defaultGraceSeconds;
    }

    public List<KeyVersionResponse> listKeys() {
        return keyVersionRepository.findAllByOrderByVersionNumberDesc()
                .stream()
                .map(this::toDto)
                .toList();
    }

    public KeyVersionEntity getActiveCommittedKey() {
        return keyVersionRepository.findFirstByStatusOrderByVersionNumberDesc("COMMITTED")
                .orElseThrow(() -> new ResourceNotFoundException("No committed active key version found"));
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
        String kemPrivRef = keyStore.storeSecret("key-v" + nextVersion + "-mlkem768-priv", kemPair.privateKey());
        keyStore.storeSecret("key-v" + nextVersion + "-dek", dek);
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
            ack.setDetailMessage("Key v" + nextVersion + " distributed; awaiting node verification");
            ackRepository.save(ack);
        }

        String actor = currentActorOrSystem();
        auditLogService.appendEvent(
                actor,
                "KEY_PREPARED_AND_DISTRIBUTED",
                alias + ":v" + nextVersion,
                "Prepared ML-KEM-768 key v" + nextVersion + " (grace=" + grace + "s) and distributed to " + nodes.size() + " nodes"
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

    @Transactional
    public KeyVersionResponse commitKey(Long keyId) {
        KeyVersionEntity candidate = keyVersionRepository.findById(keyId)
                .orElseThrow(() -> new ResourceNotFoundException("Key version not found: " + keyId));
        if ("COMMITTED".equals(candidate.getStatus())) {
            throw new ConflictException("ALREADY_COMMITTED", "Key version is already committed");
        }
        if ("RETIRED".equals(candidate.getStatus())) {
            throw new ConflictException("KEY_RETIRED", "Cannot commit a retired key version");
        }

        List<NodeKeyAcknowledgementEntity> acks = ackRepository.findByKeyVersionIdOrderByNodeIdAsc(keyId);
        List<String> unacked = acks.stream()
                .filter(a -> !"ACKNOWLEDGED".equals(a.getAckStatus()))
                .map(a -> a.getNode().getNodeCode() + "(" + a.getAckStatus() + ")")
                .toList();

        if (acks.isEmpty() || !unacked.isEmpty()) {
            String msg = "Commit blocked: required simulated nodes have not acknowledged v"
                    + candidate.getVersionNumber() + ": " + String.join(", ", unacked);
            candidate.setFailureReason(msg);
            keyVersionRepository.save(candidate);
            auditLogService.appendEvent(
                    currentActorOrSystem(),
                    "KEY_COMMIT_REJECTED",
                    candidate.getKeyAlias() + ":v" + candidate.getVersionNumber(),
                    msg
            );
            throw new ConflictException("ACK_QUORUM_NOT_MET", msg);
        }

        Instant now = Instant.now();
        KeyVersionEntity previousActive = keyVersionRepository.findFirstByStatusOrderByVersionNumberDesc("COMMITTED")
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
        for (SimulatedNodeEntity node : nodes) {
            node.setCurrentKeyVersion(candidate.getVersionNumber());
            node.setLastHeartbeatAt(now);
            nodeRepository.save(node);
        }

        // Re-wrap protected resource payloads under the newly committed DEK
        if (previousActive != null) {
            byte[] oldDek = keyStore.loadSecret("key-v" + previousActive.getVersionNumber() + "-dek");
            byte[] newDek = keyStore.loadSecret("key-v" + candidate.getVersionNumber() + "-dek");
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
                "Committed key v" + candidate.getVersionNumber() + " across " + nodes.size() + " nodes; "
                        + (previousActive != null ? "v" + previousActive.getVersionNumber() + " cutoff at " + previousActive.getCutoffTime() : "initial commit")
        );

        return toDto(candidate);
    }

    public KeyVersionEntity validateKeyUsage(Integer requestedVersion, Instant evaluationTime) {
        KeyVersionEntity active = getActiveCommittedKey();
        if (requestedVersion == null || requestedVersion == active.getVersionNumber()) {
            return active;
        }
        KeyVersionEntity requested = keyVersionRepository.findByVersionNumber(requestedVersion)
                .orElseThrow(() -> new AccessDeniedBusinessException(
                        "UNKNOWN_KEY_VERSION",
                        "Requested key version v" + requestedVersion + " does not exist"
                ));
        if ("PREPARED".equals(requested.getStatus()) || "DISTRIBUTED".equals(requested.getStatus())
                || "ACKNOWLEDGED".equals(requested.getStatus())) {
            throw new AccessDeniedBusinessException(
                    "UNCOMMITTED_KEY_VERSION",
                    "Key version v" + requestedVersion + " is not yet committed for operational use"
            );
        }
        if ("RETIRED".equals(requested.getStatus())) {
            Instant cutoff = requested.getCutoffTime();
            if (cutoff == null || !evaluationTime.isBefore(cutoff)) {
                throw new AccessDeniedBusinessException(
                        "KEY_PAST_CUTOFF",
                        "Key version v" + requestedVersion + " is retired and rejected after cutoff " + cutoff
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
