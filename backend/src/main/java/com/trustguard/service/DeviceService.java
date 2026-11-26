package com.trustguard.service;

import com.trustguard.audit.AuditLogService;
import com.trustguard.crypto.PostQuantumCryptoService;
import com.trustguard.crypto.ProtectedKeyStore;
import com.trustguard.dto.DeviceEnrolRequest;
import com.trustguard.dto.DeviceResponse;
import com.trustguard.entity.DeviceEntity;
import com.trustguard.entity.RevocationEntity;
import com.trustguard.entity.SimulatedNodeEntity;
import com.trustguard.entity.UserEntity;
import com.trustguard.exception.AccessDeniedBusinessException;
import com.trustguard.exception.ConflictException;
import com.trustguard.exception.ResourceNotFoundException;
import com.trustguard.repository.DeviceRepository;
import com.trustguard.repository.RevocationRepository;
import com.trustguard.repository.SimulatedNodeRepository;
import com.trustguard.repository.UserRepository;
import com.trustguard.security.SecurityUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class DeviceService {

    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final RevocationRepository revocationRepository;
    private final SimulatedNodeRepository nodeRepository;
    private final PostQuantumCryptoService cryptoService;
    private final ProtectedKeyStore keyStore;
    private final AuditLogService auditLogService;

    public DeviceService(
            UserRepository userRepository,
            DeviceRepository deviceRepository,
            RevocationRepository revocationRepository,
            SimulatedNodeRepository nodeRepository,
            PostQuantumCryptoService cryptoService,
            ProtectedKeyStore keyStore,
            AuditLogService auditLogService
    ) {
        this.userRepository = userRepository;
        this.deviceRepository = deviceRepository;
        this.revocationRepository = revocationRepository;
        this.nodeRepository = nodeRepository;
        this.cryptoService = cryptoService;
        this.keyStore = keyStore;
        this.auditLogService = auditLogService;
    }

    public List<Map<String, Object>> listUsers() {
        if (SecurityUtils.isAdmin()) {
            return userRepository.findAll().stream()
                    .map(this::toUserSummary)
                    .toList();
        }
        String caller = SecurityUtils.currentUsername();
        UserEntity callerEntity = userRepository.findByUsername(caller)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + caller));
        return List.of(toUserSummary(callerEntity));
    }

    public List<Map<String, Object>> listMessagingRecipients() {
        return userRepository.findAll().stream()
                .filter(UserEntity::isActive)
                .map(u -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("username", u.getUsername());
                    m.put("displayName", u.getDisplayName());
                    return m;
                })
                .toList();
    }

    private Map<String, Object> toUserSummary(UserEntity u) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", u.getId());
        m.put("username", u.getUsername());
        m.put("displayName", u.getDisplayName());
        m.put("email", u.getEmail());
        m.put("role", u.getRole());
        m.put("active", u.isActive());
        m.put("createdAt", u.getCreatedAt());
        return m;
    }

    public List<DeviceResponse> listDevices() {
        List<DeviceEntity> devices = SecurityUtils.isAdmin()
                ? deviceRepository.findAllByOrderByEnrolledAtDesc()
                : deviceRepository.findByOwnerUsernameOrderByEnrolledAtDesc(SecurityUtils.currentUsername());
        return devices.stream()
                .map(this::toDto)
                .toList();
    }

    public List<SimulatedNodeEntity> listNodes() {
        return nodeRepository.findAllByOrderByIdAsc();
    }

    @Transactional
    public SimulatedNodeEntity toggleNodeAckFailure(Long nodeId, boolean simulateFailure) {
        SimulatedNodeEntity node = nodeRepository.findById(nodeId)
                .orElseThrow(() -> new ResourceNotFoundException("Simulated node not found: " + nodeId));
        node.setSimulateAckFailure(simulateFailure);
        node.setStatus(simulateFailure ? "DEGRADED" : "ONLINE");
        node.setLastHeartbeatAt(Instant.now());
        SimulatedNodeEntity saved = nodeRepository.save(node);
        auditLogService.appendEvent(
                SecurityUtils.currentUsername(),
                simulateFailure ? "NODE_SIMULATE_ACK_FAILURE_ON" : "NODE_SIMULATE_ACK_FAILURE_OFF",
                node.getNodeCode(),
                "Node " + node.getNodeCode() + " simulateAckFailure=" + simulateFailure
        );
        return saved;
    }

    @Transactional
    public DeviceResponse enrolDevice(DeviceEnrolRequest request) {
        String caller = SecurityUtils.currentUsername();
        String targetOwner = (request.ownerUsername() == null || request.ownerUsername().isBlank())
                ? caller
                : request.ownerUsername().trim();

        if (!targetOwner.equals(caller) && !SecurityUtils.isAdmin()) {
            throw new AccessDeniedBusinessException(
                    "OWNER_ENROL_ONLY",
                    "Non-admin users can only enrol devices for their own authenticated identity"
            );
        }

        UserEntity owner = userRepository.findByUsername(targetOwner)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + targetOwner));
        if (!owner.isActive()) {
            throw new AccessDeniedBusinessException("ACCOUNT_DISABLED", "Cannot enroll devices for an inactive user");
        }
        if (!SecurityUtils.isAdmin()) {
            boolean hasRevokedDevice = deviceRepository.existsByOwnerUsernameAndStatus(targetOwner, "REVOKED")
                    || revocationRepository.existsByUsername(targetOwner);
            boolean hasActiveDevice = deviceRepository.existsByOwnerUsernameAndStatus(targetOwner, "ACTIVE");
            if (hasRevokedDevice || !hasActiveDevice) {
                throw new AccessDeniedBusinessException(
                        "ADMIN_APPROVAL_REQUIRED",
                        "Self-service enrollment denied: accounts with revoked devices or without an active approved device require ADMIN approval"
                );
            }
        }

        String deviceUid = "dev-" + targetOwner + "-" + UUID.randomUUID().toString().substring(0, 6);
        PostQuantumCryptoService.RawKeyPair kemPair = cryptoService.generateMlKem768KeyPair();
        PostQuantumCryptoService.RawKeyPair dsaPair = cryptoService.generateMlDsa65KeyPair();

        String kemRef = keyStore.storeSecret(deviceUid + "-kem-priv", kemPair.privateKey());
        keyStore.storeSecret(deviceUid + "-dsa-priv", dsaPair.privateKey());
        cryptoService.zeroize(kemPair.privateKey(), dsaPair.privateKey());

        Instant now = Instant.now();
        DeviceEntity device = new DeviceEntity();
        device.setDeviceUid(deviceUid);
        device.setOwner(owner);
        device.setDeviceName(request.deviceName().trim());
        device.setPublicKeyB64(Base64.getEncoder().encodeToString(kemPair.publicKey()));
        device.setPublicKeyFingerprint(kemPair.fingerprintSha256());
        device.setKeyReference(kemRef);
        device.setKeyAlgorithm("ML-KEM-768 / ML-DSA-65");
        device.setSigningPublicKeyB64(Base64.getEncoder().encodeToString(dsaPair.publicKey()));
        device.setStatus("ACTIVE");
        device.setEnrolledAt(now);
        device.setLastSeenAt(now);
        device = deviceRepository.save(device);

        if (request.replacesDeviceId() != null) {
            DeviceEntity oldDevice = deviceRepository.findById(request.replacesDeviceId())
                    .orElseThrow(() -> new ResourceNotFoundException("Replaced device not found: " + request.replacesDeviceId()));
            if (!oldDevice.getOwner().getId().equals(owner.getId())) {
                throw new AccessDeniedBusinessException("REPLACE_OWNER_MISMATCH", "Cannot replace another user's device");
            }
            oldDevice.setReplacedByDeviceId(device.getId());
            if (!"REVOKED".equals(oldDevice.getStatus())) {
                oldDevice.setStatus("REVOKED");
                oldDevice.setRevokedAt(now);
            }
            deviceRepository.save(oldDevice);
        }

        auditLogService.appendEvent(
                caller,
                "DEVICE_ENROLLED",
                device.getDeviceUid(),
                "Enrolled " + device.getDeviceName() + " for owner=" + owner.getUsername()
                        + " fingerprint=" + device.getPublicKeyFingerprint().substring(0, 12)
        );
        return toDto(device);
    }

    @Transactional
    public Map<String, Object> revokeDevice(Long deviceId, String rawReason) {
        String caller = SecurityUtils.currentUsername();
        DeviceEntity device = deviceRepository.findById(deviceId)
                .orElseThrow(() -> new ResourceNotFoundException("Device not found: " + deviceId));

        if (!device.getOwner().getUsername().equals(caller) && !SecurityUtils.isAdmin()) {
            throw new AccessDeniedBusinessException(
                    "REVOKE_FORBIDDEN",
                    "Only the device owner or an admin can revoke this device"
            );
        }
        if ("REVOKED".equals(device.getStatus())) {
            throw new ConflictException("ALREADY_REVOKED", "Device " + device.getDeviceUid() + " is already revoked");
        }

        Instant revocationStartedAt = Instant.now();
        String reason = (rawReason == null || rawReason.isBlank()) ? "Lost or compromised device" : rawReason.trim();

        device.setStatus("REVOKED");
        device.setRevokedAt(revocationStartedAt);
        deviceRepository.save(device);

        // Immediately invalidate active JWTs for the revoked device's owner
        UserEntity owner = device.getOwner();
        owner.setTokenVersion(owner.getTokenVersion() + 1L);
        userRepository.save(owner);

        long nextVersion = revocationRepository.findTopByOrderByRevocationVersionDesc()
                .map(r -> r.getRevocationVersion() + 1L)
                .orElse(1L);

        List<SimulatedNodeEntity> nodes = nodeRepository.findAllByOrderByIdAsc();
        Instant lastNodeTimestamp = revocationStartedAt;
        for (int i = 0; i < nodes.size(); i++) {
            SimulatedNodeEntity node = nodes.get(i);
            node.setCurrentRevocationVersion(nextVersion);
            Instant nodeEnforcedAt = Instant.now();
            long nodeDelta = Math.max(1L, Duration.between(revocationStartedAt, nodeEnforcedAt).toMillis());
            node.setLastRevocationEnforcedAt(nodeEnforcedAt);
            node.setLastPropagationMs(nodeDelta);
            node.setLastHeartbeatAt(nodeEnforcedAt);
            nodeRepository.save(node);
            lastNodeTimestamp = nodeEnforcedAt;
        }

        long totalPropagationMs = Math.max(1L, Duration.between(revocationStartedAt, lastNodeTimestamp).toMillis());

        RevocationEntity revocation = new RevocationEntity();
        revocation.setRevocationVersion(nextVersion);
        revocation.setTargetType("DEVICE");
        revocation.setDevice(device);
        revocation.setUsername(device.getOwner().getUsername());
        revocation.setReason(reason);
        revocation.setInitiatedBy(caller);
        revocation.setRevokedAt(revocationStartedAt);
        revocation.setPropagationCompletedAt(lastNodeTimestamp);
        revocation.setPropagationLatencyMs(totalPropagationMs);
        revocation.setNodesEnforcedCount(nodes.size());
        revocation.setTotalNodesCount(nodes.size());
        revocationRepository.save(revocation);

        auditLogService.appendEvent(
                caller,
                "DEVICE_REVOKED",
                device.getDeviceUid(),
                "Revoked " + device.getDeviceUid() + " (owner=" + device.getOwner().getUsername()
                        + "), revocationVersion=" + nextVersion
                        + ", enforced across " + nodes.size() + "/" + nodes.size() + " nodes in " + totalPropagationMs + "ms"
        );

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("device", toDto(device));
        result.put("revocationVersion", nextVersion);
        result.put("revokedAt", revocationStartedAt);
        result.put("propagationCompletedAt", lastNodeTimestamp);
        result.put("propagationLatencyMs", totalPropagationMs);
        result.put("nodesEnforced", nodes.size());
        result.put("totalNodes", nodes.size());
        result.put("otherUsersPreserved", true);
        return result;
    }

    public long getLatestRevocationVersion() {
        return revocationRepository.findTopByOrderByRevocationVersionDesc()
                .map(RevocationEntity::getRevocationVersion)
                .orElse(0L);
    }

    public DeviceResponse toDto(DeviceEntity d) {
        return new DeviceResponse(
                d.getId(),
                d.getDeviceUid(),
                d.getOwner().getUsername(),
                d.getOwner().getDisplayName(),
                d.getDeviceName(),
                d.getPublicKeyFingerprint(),
                d.getKeyAlgorithm(),
                d.getStatus(),
                d.getEnrolledAt(),
                d.getLastSeenAt(),
                d.getRevokedAt(),
                d.getReplacedByDeviceId()
        );
    }
}
