package com.trustguard.service;

import com.trustguard.audit.AuditLogService;
import com.trustguard.crypto.PostQuantumCryptoService;
import com.trustguard.crypto.ProtectedKeyStore;
import com.trustguard.dto.AccessCheckRequest;
import com.trustguard.dto.AccessCheckResponse;
import com.trustguard.entity.AccessEventEntity;
import com.trustguard.entity.DeviceEntity;
import com.trustguard.entity.KeyVersionEntity;
import com.trustguard.entity.ResourceEntity;
import com.trustguard.entity.RolePermissionEntity;
import com.trustguard.entity.SecurityAlertEntity;
import com.trustguard.entity.SimulatedNodeEntity;
import com.trustguard.entity.UserEntity;
import com.trustguard.exception.AccessDeniedBusinessException;
import com.trustguard.exception.ConflictException;
import com.trustguard.exception.ResourceNotFoundException;
import com.trustguard.repository.AccessEventRepository;
import com.trustguard.repository.DeviceRepository;
import com.trustguard.repository.ResourceRepository;
import com.trustguard.repository.RolePermissionRepository;
import com.trustguard.repository.SecurityAlertRepository;
import com.trustguard.repository.SimulatedNodeRepository;
import com.trustguard.repository.UserRepository;
import com.trustguard.security.SecurityUtils;
import com.trustguard.util.CanonicalJsonUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class AccessControlService {

    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final ResourceRepository resourceRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final SimulatedNodeRepository nodeRepository;
    private final AccessEventRepository accessEventRepository;
    private final SecurityAlertRepository securityAlertRepository;
    private final KeyManagementService keyManagementService;
    private final DeviceService deviceService;
    private final PostQuantumCryptoService cryptoService;
    private final ProtectedKeyStore keyStore;
    private final AuditLogService auditLogService;

    public AccessControlService(
            UserRepository userRepository,
            DeviceRepository deviceRepository,
            ResourceRepository resourceRepository,
            RolePermissionRepository rolePermissionRepository,
            SimulatedNodeRepository nodeRepository,
            AccessEventRepository accessEventRepository,
            SecurityAlertRepository securityAlertRepository,
            KeyManagementService keyManagementService,
            DeviceService deviceService,
            PostQuantumCryptoService cryptoService,
            ProtectedKeyStore keyStore,
            AuditLogService auditLogService
    ) {
        this.userRepository = userRepository;
        this.deviceRepository = deviceRepository;
        this.resourceRepository = resourceRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.nodeRepository = nodeRepository;
        this.accessEventRepository = accessEventRepository;
        this.securityAlertRepository = securityAlertRepository;
        this.keyManagementService = keyManagementService;
        this.deviceService = deviceService;
        this.cryptoService = cryptoService;
        this.keyStore = keyStore;
        this.auditLogService = auditLogService;
    }

    public List<Map<String, Object>> listResources() {
        return resourceRepository.findAllByOrderByIdAsc().stream()
                .map(r -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", r.getId());
                    m.put("resourceKey", r.getResourceKey());
                    m.put("title", r.getTitle());
                    m.put("ownerUsername", r.getOwner().getUsername());
                    m.put("allowedServices", r.getAllowedServices());
                    m.put("classification", r.getClassification());
                    m.put("activeKeyVersion", r.getActiveKeyVersion().getVersionNumber());
                    m.put("updatedAt", r.getUpdatedAt());
                    return m;
                })
                .toList();
    }

    public List<Map<String, Object>> listAccessEvents() {
        return accessEventRepository.findTop100ByOrderByTimestampUtcDesc().stream()
                .map(e -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", e.getId());
                    m.put("requestId", e.getRequestId());
                    m.put("actor", e.getActorUsername());
                    m.put("authenticatedPrincipal", e.getAuthenticatedPrincipal());
                    m.put("demoSimulation", e.isSimulationMode());
                    m.put("deviceUid", e.getDevice() != null ? e.getDevice().getDeviceUid() : "none");
                    m.put("sourceService", e.getSourceService());
                    m.put("targetService", e.getTargetService());
                    m.put("resource", e.getResourceKey());
                    m.put("action", e.getAction());
                    m.put("decision", e.getDecision());
                    m.put("reason", e.getDecisionReason());
                    m.put("keyVersionUsed", e.getKeyVersionUsed());
                    m.put("nodeCode", e.getNodeCode());
                    m.put("timestampUtc", e.getTimestampUtc());
                    return m;
                })
                .toList();
    }

    @Transactional
    public AccessCheckResponse checkAccess(AccessCheckRequest req) {
        String authenticatedPrincipal = SecurityUtils.currentUsername();
        boolean simulationMode = req.simulationMode();
        String actorUsername = authenticatedPrincipal;

        if (req.simulatedActor() != null && !req.simulatedActor().isBlank() && !req.simulatedActor().equals(authenticatedPrincipal)) {
            if (!simulationMode || !SecurityUtils.isAdmin()) {
                throw new AccessDeniedBusinessException(
                        "ACTOR_IMPERSONATION_BLOCKED",
                        "Clients cannot submit arbitrary trusted actor names without admin demo simulation mode"
                );
            }
            actorUsername = req.simulatedActor().trim();
        }

        String requestId = (req.requestId() != null && !req.requestId().isBlank())
                ? req.requestId().trim()
                : "req-" + UUID.randomUUID().toString().substring(0, 12);

        if (accessEventRepository.findByRequestId(requestId).isPresent()) {
            throw new ConflictException("DUPLICATE_REQUEST_ID", "Request ID already recorded: " + requestId);
        }

        Instant now = Instant.now();
        String nodeCode = (req.nodeCode() != null && !req.nodeCode().isBlank()) ? req.nodeCode().trim() : "node-alpha";
        SimulatedNodeEntity node = nodeRepository.findByNodeCode(nodeCode)
                .orElseThrow(() -> new ResourceNotFoundException("Unknown simulated node: " + nodeCode));

        UserEntity actor = userRepository.findByUsername(actorUsername).orElse(null);
        ResourceEntity resource = resourceRepository.findByResourceKey(req.resourceKey()).orElse(null);
        DeviceEntity device = resolveDevice(req.deviceId(), actorUsername);

        KeyVersionEntity keyVersion = keyManagementService.getActiveCommittedKey();
        String decision = "DENY";
        String reason = "Access denied by default";

        long latestRevocationVersion = deviceService.getLatestRevocationVersion();

        if (actor == null || !actor.isActive()) {
            reason = "Unknown or inactive actor identity";
        } else if (device == null) {
            reason = "No enrolled device presented for actor " + actorUsername;
        } else if (!device.getOwner().getUsername().equals(actorUsername)) {
            reason = "Device " + device.getDeviceUid() + " does not belong to actor " + actorUsername;
        } else if ("REVOKED".equals(device.getStatus()) || node.getCurrentRevocationVersion() < latestRevocationVersion) {
            reason = "REVOKED_DEVICE: Device " + device.getDeviceUid() + " rejected on node " + node.getNodeCode()
                    + " (revocation v" + node.getCurrentRevocationVersion() + ")";
            recordLiveAlert(
                    "revoked_identity_activity",
                    "HIGH",
                    "DENIED_ATTEMPT",
                    actorUsername,
                    req.sourceService() + " -> " + req.targetService(),
                    requestId,
                    "Denied access attempt using revoked device " + device.getDeviceUid() + " on " + node.getNodeCode()
            );
        } else if (resource == null) {
            reason = "Requested resource does not exist";
        } else {
            boolean keyCheckPassed = true;
            if (req.requestedKeyVersion() != null) {
                try {
                    keyVersion = keyManagementService.validateKeyUsage(req.requestedKeyVersion(), now);
                } catch (AccessDeniedBusinessException ex) {
                    keyCheckPassed = false;
                    reason = ex.getMessage();
                }
            }

            if (keyCheckPassed) {
                List<String> allowedServices = Arrays.stream(resource.getAllowedServices().split(","))
                        .map(String::trim)
                        .toList();
                boolean serviceAllowedForResource = allowedServices.contains(req.targetService());
                boolean isOwner = resource.getOwner().getUsername().equals(actorUsername);
                Optional<RolePermissionEntity> rolePerm = rolePermissionRepository
                        .findByRoleNameAndServiceNameAndTargetServiceAndAction(
                                actor.getRole(), req.sourceService(), req.targetService(), req.action()
                        );
                boolean roleAllowsService = rolePerm.map(RolePermissionEntity::isAllowed).orElse(false);

                if (!serviceAllowedForResource || !roleAllowsService) {
                    reason = "UNAUTHORIZED_SERVICE: Role " + actor.getRole() + " or resource policy denies "
                            + req.sourceService() + " -> " + req.targetService() + " (" + req.action() + ")";
                    recordLiveAlert(
                            "service_access_outside_approved_scope",
                            "MEDIUM",
                            "DENIED_ATTEMPT",
                            actorUsername,
                            req.sourceService() + " -> " + req.targetService(),
                            requestId,
                            "Denied service access attempt outside policy scope: " + reason
                    );
                } else if (!isOwner && !"ADMIN".equalsIgnoreCase(actor.getRole())) {
                    reason = "WRONG_OWNER: Resource " + resource.getResourceKey() + " is owned by "
                            + resource.getOwner().getUsername() + ", not " + actorUsername;
                    recordLiveAlert(
                            "isolated_denied_request",
                            "LOW",
                            "DENIED_ATTEMPT",
                            actorUsername,
                            req.sourceService() + " -> " + req.targetService(),
                            requestId,
                            "Single denied cross-owner read for " + resource.getResourceKey()
                    );
                } else {
                    decision = "ALLOW";
                    reason = isOwner ? "Owner & active device verified" : "Admin verified on active device";
                    device.setLastSeenAt(now);
                    deviceRepository.save(device);
                }
            }
        }

        AccessEventEntity event = new AccessEventEntity();
        event.setRequestId(requestId);
        event.setActorUsername(actorUsername);
        event.setAuthenticatedPrincipal(authenticatedPrincipal);
        event.setSimulationMode(simulationMode);
        event.setDevice(device);
        event.setSourceService(req.sourceService());
        event.setTargetService(req.targetService());
        event.setResourceKey(req.resourceKey());
        event.setAction(req.action());
        event.setDecision(decision);
        event.setDecisionReason(reason);
        event.setKeyVersionUsed(keyVersion.getVersionNumber());
        event.setNodeCode(node.getNodeCode());
        event.setTimestampUtc(now);
        event.setCreatedAt(now);
        accessEventRepository.save(event);

        String auditActor = simulationMode ? (authenticatedPrincipal + "[sim:" + actorUsername + "]") : authenticatedPrincipal;
        auditLogService.appendEvent(
                auditActor,
                "ACCESS_" + decision,
                req.resourceKey(),
                "requestId=" + requestId + " node=" + node.getNodeCode() + " reason=" + reason
        );

        String body = null;
        String ciphertextB64 = null;
        String proofHex = null;

        if ("ALLOW".equals(decision) && resource != null) {
            byte[] dek = keyStore.loadSecret("key-v" + resource.getActiveKeyVersion().getVersionNumber() + "-dek");
            String plaintext;
            try {
                plaintext = cryptoService.decryptAes256Gcm(
                        dek,
                        resource.getContentIvB64(),
                        resource.getContentCiphertextB64(),
                        resource.getContentAad()
                );
            } finally {
                cryptoService.zeroize(dek);
            }

            if (req.protectedRead()) {
                if (req.publicKeyB64() == null || req.publicKeyB64().isBlank() || req.challenge() == null) {
                    throw new IllegalArgumentException("protectedRead requires publicKeyB64 and challenge");
                }
                byte[] pkBytes = Base64.getDecoder().decode(req.publicKeyB64().trim());
                PostQuantumCryptoService.KemEncapsulation encap = cryptoService.encapsulateMlKem768(pkBytes);
                try {
                    ciphertextB64 = Base64.getEncoder().encodeToString(encap.ciphertext());
                    proofHex = cryptoService.computeProtectedReadProof(encap.sharedSecret(), req.challenge(), plaintext);
                } finally {
                    cryptoService.zeroize(encap.sharedSecret());
                }
            } else {
                body = plaintext;
            }
        }

        return new AccessCheckResponse(
                requestId,
                decision,
                reason,
                actorUsername,
                authenticatedPrincipal,
                simulationMode,
                device != null ? device.getDeviceUid() : null,
                req.sourceService(),
                req.targetService(),
                req.resourceKey(),
                node.getNodeCode(),
                keyVersion.getVersionNumber(),
                now,
                body,
                ciphertextB64,
                proofHex
        );
    }

    private DeviceEntity resolveDevice(Long deviceId, String actorUsername) {
        if (deviceId != null) {
            return deviceRepository.findById(deviceId).orElse(null);
        }
        return deviceRepository.findFirstByOwnerUsernameAndStatusOrderByEnrolledAtDesc(actorUsername, "ACTIVE")
                .orElseGet(() -> deviceRepository.findByOwnerUsernameOrderByEnrolledAtDesc(actorUsername)
                        .stream().findFirst().orElse(null));
    }

    private void recordLiveAlert(
            String ruleName,
            String severity,
            String outcomeClassification,
            String actor,
            String servicePath,
            String requestId,
            String explanation
    ) {
        SecurityAlertEntity alert = new SecurityAlertEntity();
        alert.setAlertUid("alt-" + UUID.randomUUID().toString().substring(0, 10));
        alert.setRuleName(ruleName);
        alert.setSeverity(severity);
        alert.setOutcomeClassification(outcomeClassification);
        alert.setActor(actor);
        alert.setServicePath(servicePath);
        alert.setEventIdsJson(CanonicalJsonUtil.toCanonicalJson(List.of(requestId)));
        alert.setDetectedAt(Instant.now());
        alert.setSourceEventTimeUtc(Instant.now());
        alert.setDetectionLatencyMs(1L);
        alert.setExplanation(explanation);
        alert.setDatasetSource("LIVE_RUNTIME");
        securityAlertRepository.save(alert);
    }
}
