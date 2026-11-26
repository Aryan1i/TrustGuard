package com.trustguard.service;

import com.trustguard.audit.AuditLogService;
import com.trustguard.crypto.PostQuantumCryptoService;
import com.trustguard.dto.AccessCheckRequest;
import com.trustguard.dto.AccessCheckResponse;
import com.trustguard.entity.AccessEventEntity;
import com.trustguard.entity.DeviceEntity;
import com.trustguard.entity.KeyVersionEntity;
import com.trustguard.entity.ResourceEntity;
import com.trustguard.entity.RolePermissionEntity;
import com.trustguard.entity.SimulatedNodeEntity;
import com.trustguard.entity.UserEntity;
import com.trustguard.exception.AccessDeniedBusinessException;
import com.trustguard.exception.ConflictException;
import com.trustguard.exception.ResourceNotFoundException;
import com.trustguard.repository.AccessEventRepository;
import com.trustguard.repository.DeviceRepository;
import com.trustguard.repository.ResourceRepository;
import com.trustguard.repository.RolePermissionRepository;
import com.trustguard.repository.SimulatedNodeRepository;
import com.trustguard.repository.UserRepository;
import com.trustguard.security.SecurityUtils;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class AccessControlService {

    private static final int AUDIT_ACTOR_MAX_LEN = 64;
    private static final int LOCK_STRIPES = 512;

    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final ResourceRepository resourceRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final SimulatedNodeRepository nodeRepository;
    private final AccessEventRepository accessEventRepository;
    private final KeyManagementService keyManagementService;
    private final DeviceService deviceService;
    private final PostQuantumCryptoService cryptoService;
    private final AuditLogService auditLogService;
    private final SecurityPersistenceService persistenceService;
    private final ReentrantLock[] requestIdLocks = new ReentrantLock[LOCK_STRIPES];

    public AccessControlService(
            UserRepository userRepository,
            DeviceRepository deviceRepository,
            ResourceRepository resourceRepository,
            RolePermissionRepository rolePermissionRepository,
            SimulatedNodeRepository nodeRepository,
            AccessEventRepository accessEventRepository,
            KeyManagementService keyManagementService,
            DeviceService deviceService,
            PostQuantumCryptoService cryptoService,
            AuditLogService auditLogService,
            SecurityPersistenceService persistenceService
    ) {
        this.userRepository = userRepository;
        this.deviceRepository = deviceRepository;
        this.resourceRepository = resourceRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.nodeRepository = nodeRepository;
        this.accessEventRepository = accessEventRepository;
        this.keyManagementService = keyManagementService;
        this.deviceService = deviceService;
        this.cryptoService = cryptoService;
        this.auditLogService = auditLogService;
        this.persistenceService = persistenceService;
        for (int i = 0; i < LOCK_STRIPES; i++) {
            this.requestIdLocks[i] = new ReentrantLock();
        }
    }

    public List<Map<String, Object>> listResources() {
        List<ResourceEntity> resources = SecurityUtils.isAdmin()
                ? resourceRepository.findAllByOrderByIdAsc()
                : resourceRepository.findByOwnerUsernameOrderByIdAsc(SecurityUtils.currentUsername());
        return resources.stream()
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
        List<AccessEventEntity> events;
        if (SecurityUtils.isAdmin()) {
            events = accessEventRepository.findTop100ByOrderByTimestampUtcDesc();
        } else {
            String caller = SecurityUtils.currentUsername();
            events = accessEventRepository.findTop100ByActorUsernameOrAuthenticatedPrincipalOrderByTimestampUtcDesc(caller, caller);
        }
        return events.stream()
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

    private record PendingLiveAlert(
            String ruleName,
            String severity,
            String actor,
            String servicePath,
            String explanation
    ) {
    }

    private record AccessEvaluationTxOutcome(
            AccessCheckResponse response,
            String auditActor,
            String decision,
            String nodeCode,
            String reason,
            PendingLiveAlert pendingAlert
    ) {
    }

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

        byte[] validatedProtectedReadPk = null;
        if (req.protectedRead()) {
            if (req.publicKeyB64() == null || req.publicKeyB64().isBlank() || req.challenge() == null) {
                throw new IllegalArgumentException("protectedRead requires publicKeyB64 and challenge");
            }
            try {
                validatedProtectedReadPk = Base64.getDecoder().decode(req.publicKeyB64().trim());
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("protectedRead publicKeyB64 must be valid Base64", ex);
            }
            cryptoService.validateMlKem768PublicKey(validatedProtectedReadPk);
        }

        String requestId = (req.requestId() != null && !req.requestId().isBlank())
                ? req.requestId().trim()
                : "req-" + UUID.randomUUID().toString().substring(0, 12);

        String resolvedActorUsername = actorUsername;
        byte[] finalProtectedReadPk = validatedProtectedReadPk;

        ReentrantLock lock = requestIdLocks[Math.floorMod(requestId.hashCode(), LOCK_STRIPES)];
        AccessEvaluationTxOutcome outcome;
        lock.lock();
        try {
            outcome = persistenceService.inTransaction(() -> evaluateAndPersistAccess(
                    req,
                    requestId,
                    resolvedActorUsername,
                    authenticatedPrincipal,
                    simulationMode,
                    finalProtectedReadPk
            ));
        } finally {
            lock.unlock();
        }

        if (outcome.pendingAlert() != null) {
            PendingLiveAlert alert = outcome.pendingAlert();
            persistenceService.recordLiveAlertInNewTx(
                    "alt",
                    alert.ruleName(),
                    alert.severity(),
                    "DENIED_ATTEMPT",
                    alert.actor(),
                    alert.servicePath(),
                    requestId,
                    alert.explanation()
            );
        }

        auditLogService.appendEvent(
                outcome.auditActor(),
                "ACCESS_" + outcome.decision(),
                req.resourceKey(),
                "requestId=" + requestId + " actor=" + resolvedActorUsername
                        + " node=" + outcome.nodeCode() + " reason=" + outcome.reason()
        );

        return outcome.response();
    }

    private AccessEvaluationTxOutcome evaluateAndPersistAccess(
            AccessCheckRequest req,
            String requestId,
            String actorUsername,
            String authenticatedPrincipal,
            boolean simulationMode,
            byte[] validatedProtectedReadPk
    ) {
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
        PendingLiveAlert pendingAlert = null;

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
            pendingAlert = new PendingLiveAlert(
                    "revoked_identity_activity",
                    "HIGH",
                    actorUsername,
                    req.sourceService() + " -> " + req.targetService(),
                    "Denied access attempt using revoked device " + device.getDeviceUid() + " on " + node.getNodeCode()
            );
        } else if (resource == null) {
            reason = "Requested resource does not exist";
        } else {
            boolean keyCheckPassed = true;
            if (req.requestedKeyVersion() != null) {
                try {
                    keyVersion = keyManagementService.validateKeyUsage(
                            resource.getActiveKeyVersion().getKeyAlias(),
                            req.requestedKeyVersion(),
                            now
                    );
                } catch (AccessDeniedBusinessException ex) {
                    keyCheckPassed = false;
                    reason = ex.getMessage();
                }
            } else {
                keyVersion = keyManagementService.getActiveCommittedKey(resource.getActiveKeyVersion().getKeyAlias());
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
                    pendingAlert = new PendingLiveAlert(
                            "service_access_outside_approved_scope",
                            "MEDIUM",
                            actorUsername,
                            req.sourceService() + " -> " + req.targetService(),
                            "Denied service access attempt outside policy scope: " + reason
                    );
                } else if (!isOwner && !"ADMIN".equalsIgnoreCase(actor.getRole())) {
                    reason = "WRONG_OWNER: Resource " + resource.getResourceKey() + " is owned by "
                            + resource.getOwner().getUsername() + ", not " + actorUsername;
                    pendingAlert = new PendingLiveAlert(
                            "isolated_denied_request",
                            "LOW",
                            actorUsername,
                            req.sourceService() + " -> " + req.targetService(),
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
        event.setActorUsername(truncate(actorUsername, 64));
        event.setAuthenticatedPrincipal(truncate(authenticatedPrincipal, 64));
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
        try {
            accessEventRepository.saveAndFlush(event);
        } catch (DataIntegrityViolationException ex) {
            throw new ConflictException("DUPLICATE_REQUEST_ID", "Request ID already recorded: " + requestId);
        }

        String body = null;
        String ciphertextB64 = null;
        String proofHex = null;

        if ("ALLOW".equals(decision) && resource != null) {
            byte[] dek = keyManagementService.loadDek(resource.getActiveKeyVersion());
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
                PostQuantumCryptoService.KemEncapsulation encap = cryptoService.encapsulateMlKem768(validatedProtectedReadPk);
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

        AccessCheckResponse response = new AccessCheckResponse(
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
        return new AccessEvaluationTxOutcome(
                response,
                formatAuditActor(authenticatedPrincipal, actorUsername, simulationMode),
                decision,
                node.getNodeCode(),
                reason,
                pendingAlert
        );
    }

    static String formatAuditActor(String authenticatedPrincipal, String actorUsername, boolean simulationMode) {
        String base = simulationMode ? (authenticatedPrincipal + "[sim:" + actorUsername + "]") : authenticatedPrincipal;
        return truncate(base, AUDIT_ACTOR_MAX_LEN);
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max);
    }

    private DeviceEntity resolveDevice(Long deviceId, String actorUsername) {
        if (deviceId != null) {
            return deviceRepository.findById(deviceId).orElse(null);
        }
        return deviceRepository.findFirstByOwnerUsernameAndStatusOrderByEnrolledAtDesc(actorUsername, "ACTIVE")
                .orElseGet(() -> deviceRepository.findByOwnerUsernameOrderByEnrolledAtDesc(actorUsername)
                        .stream().findFirst().orElse(null));
    }
}
