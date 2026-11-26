package com.trustguard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.audit.AuditLogService;
import com.trustguard.config.DataInitializer;
import com.trustguard.crypto.PostQuantumCryptoService;
import com.trustguard.crypto.ProtectedKeyStore;
import com.trustguard.detection.DetectionOrchestrationService;
import com.trustguard.entity.AuditLogEntity;
import com.trustguard.entity.BackupRecordEntity;
import com.trustguard.entity.DeviceEntity;
import com.trustguard.entity.ResourceEntity;
import com.trustguard.entity.SecureMessageEntity;
import com.trustguard.entity.SecurityAlertEntity;
import com.trustguard.entity.UserEntity;
import com.trustguard.repository.AccessEventRepository;
import com.trustguard.repository.AuditLogRepository;
import com.trustguard.repository.BackupRecordRepository;
import com.trustguard.repository.DeviceRepository;
import com.trustguard.repository.KeyVersionRepository;
import com.trustguard.repository.NodeKeyAcknowledgementRepository;
import com.trustguard.repository.ResourceRepository;
import com.trustguard.repository.RolePermissionRepository;
import com.trustguard.repository.SecureMessageRepository;
import com.trustguard.repository.SecurityAlertRepository;
import com.trustguard.repository.SimulatedNodeRepository;
import com.trustguard.repository.UserRepository;
import com.trustguard.security.AuthRateLimiter;
import com.trustguard.security.JwtService;
import com.trustguard.service.KeyManagementService;
import com.trustguard.util.HashUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class SecurityHardeningRegressionTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private DeviceRepository deviceRepository;

    @Autowired
    private SecureMessageRepository messageRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private SecurityAlertRepository alertRepository;

    @Autowired
    private BackupRecordRepository backupRecordRepository;

    @Autowired
    private ResourceRepository resourceRepository;

    @Autowired
    private KeyManagementService keyManagementService;

    @Autowired
    private ProtectedKeyStore keyStore;

    @Autowired
    private PostQuantumCryptoService cryptoService;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AccessEventRepository accessEventRepository;

    @Autowired
    private AuthRateLimiter authRateLimiter;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private KeyVersionRepository keyVersionRepository;

    @Autowired
    private SimulatedNodeRepository nodeRepository;

    @Autowired
    private NodeKeyAcknowledgementRepository ackRepository;

    @Autowired
    private RolePermissionRepository rolePermissionRepository;

    @Autowired
    private DetectionOrchestrationService detectionService;

    private String adminToken;
    private String aliceToken;
    private String bobToken;
    private String charlieToken;

    @BeforeEach
    void setUpTokens() throws Exception {
        adminToken = login("admin", "TrustGuard!Demo2026");
        aliceToken = login("alice", "TrustGuard!Demo2026");
        bobToken = login("bob", "TrustGuard!Demo2026");
        charlieToken = login("charlie", "TrustGuard!Demo2026");
    }

    private String login(String username, String password) throws Exception {
        MvcResult res = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("username", username, "password", password))))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(res.getResponse().getContentAsString()).get("token").asText();
    }

    @Test
    void messagingRejectsCrossUserDeviceIdsAndUnauthorizedReceiveNeverMutatesMessageOrErasesKey() throws Exception {
        DeviceEntity aliceDev = deviceRepository.findFirstByOwnerUsernameAndStatusOrderByEnrolledAtDesc("alice", "ACTIVE").orElseThrow();
        DeviceEntity bobDev = deviceRepository.findFirstByOwnerUsernameAndStatusOrderByEnrolledAtDesc("bob", "ACTIVE").orElseThrow();
        DeviceEntity charlieDev = deviceRepository.findFirstByOwnerUsernameAndStatusOrderByEnrolledAtDesc("charlie", "ACTIVE").orElseThrow();

        // 1. Cross-user senderDeviceId MUST be rejected with 403
        mockMvc.perform(post("/api/v1/messages")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "recipientUsername", "bob",
                                "senderDeviceId", bobDev.getId(),
                                "plaintext", "Spoofed sender device test"
                        ))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("DEVICE_OWNER_MISMATCH"));

        // 2. Cross-user recipientDeviceId MUST be rejected with 403
        mockMvc.perform(post("/api/v1/messages")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "recipientUsername", "bob",
                                "recipientDeviceId", charlieDev.getId(),
                                "plaintext", "Spoofed recipient device test"
                        ))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("DEVICE_OWNER_MISMATCH"));

        // 3. Valid send from alice -> bob
        String msgId = "reg-idor-" + UUID.randomUUID().toString().substring(0, 8);
        mockMvc.perform(post("/api/v1/messages")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "recipientUsername", "bob",
                                "senderDeviceId", aliceDev.getId(),
                                "recipientDeviceId", bobDev.getId(),
                                "plaintext", "Top secret for Bob only",
                                "customMessageId", msgId
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SENT"));

        // 4. Unauthorized caller (charlie) invoking receiveMessage CANNOT mutate status/verificationOutcome or erase key
        mockMvc.perform(post("/api/v1/messages/" + msgId + "/receive")
                        .header("Authorization", "Bearer " + charlieToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/v1/messages/" + msgId + "/receive")
                        .header("Authorization", "Bearer " + charlieToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"claimedRecipientUsername\":\"bob\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("RECIPIENT_IMPERSONATION"));

        SecureMessageEntity unchanged = messageRepository.findByMessageId(msgId).orElseThrow();
        assertEquals("SENT", unchanged.getStatus());
        assertEquals("PENDING_DELIVERY", unchanged.getVerificationOutcome());
        assertTrue(keyStore.contains(unchanged.getEphemeralKeyId() + "-priv"));

        // 5. Bob can still cleanly decrypt once
        mockMvc.perform(post("/api/v1/messages/" + msgId + "/receive")
                        .header("Authorization", "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DELIVERED"))
                .andExpect(jsonPath("$.decryptedPlaintext").value("Top secret for Bob only"));

        assertFalse(keyStore.contains(unchanged.getEphemeralKeyId() + "-priv"));

        // 6. Replay by Bob persists alert & audit event across 409 exception rollback boundary
        long replayAlertsBefore = alertRepository.findAllByOrderByDetectedAtDesc().stream()
                .filter(a -> "duplicate_replayed_message_id".equals(a.getRuleName()))
                .count();
        long replayAuditsBefore = auditLogRepository.findAllByOrderBySeqNumberDesc().stream()
                .filter(a -> "SECURE_MESSAGE_REPLAY_BLOCKED".equals(a.getAction()))
                .count();

        mockMvc.perform(post("/api/v1/messages/" + msgId + "/receive")
                        .header("Authorization", "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("REPLAY_DETECTED"));

        long replayAlertsAfter = alertRepository.findAllByOrderByDetectedAtDesc().stream()
                .filter(a -> "duplicate_replayed_message_id".equals(a.getRuleName()))
                .count();
        long replayAuditsAfter = auditLogRepository.findAllByOrderBySeqNumberDesc().stream()
                .filter(a -> "SECURE_MESSAGE_REPLAY_BLOCKED".equals(a.getAction()))
                .count();
        assertEquals(replayAlertsBefore + 1, replayAlertsAfter);
        assertEquals(replayAuditsBefore + 1, replayAuditsAfter);
    }

    @Test
    void failedOperationsPersistAuditAndPreserveEphemeralKeyOnAesGcmFailure() throws Exception {
        // 1. KEY_COMMIT_REJECTED persists audit event even though commit throws 409 Conflict
        MvcResult prepRes = mockMvc.perform(post("/api/v1/keys/prepare")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyAlias\":\"audit-persist-key\",\"gracePeriodSeconds\":30}"))
                .andExpect(status().isOk())
                .andReturn();
        long keyId = objectMapper.readTree(prepRes.getResponse().getContentAsString()).get("id").asLong();

        long commitRejBefore = auditLogRepository.findAllByOrderBySeqNumberDesc().stream()
                .filter(a -> "KEY_COMMIT_REJECTED".equals(a.getAction()))
                .count();

        mockMvc.perform(post("/api/v1/keys/" + keyId + "/commit")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ACK_QUORUM_NOT_MET"));

        long commitRejAfter = auditLogRepository.findAllByOrderBySeqNumberDesc().stream()
                .filter(a -> "KEY_COMMIT_REJECTED".equals(a.getAction()))
                .count();
        assertEquals(commitRejBefore + 1, commitRejAfter);

        // 2. Corrupted ciphertext with AES-GCM failure marks message REJECTED permanently without losing audit or consuming key before verification
        String gcmFailMsgId = "reg-gcmfail-" + UUID.randomUUID().toString().substring(0, 8);
        mockMvc.perform(post("/api/v1/messages")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "recipientUsername", "bob",
                                "plaintext", "Corrupted payload test",
                                "customMessageId", gcmFailMsgId,
                                "simulateTamperedCiphertext", true
                        ))))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/messages/" + gcmFailMsgId + "/receive")
                        .header("Authorization", "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("CIPHERTEXT_INVALID"));

        SecureMessageEntity failedMsg = messageRepository.findByMessageId(gcmFailMsgId).orElseThrow();
        assertEquals("REJECTED", failedMsg.getStatus());
        assertEquals("AES_GCM_AUTH_FAILED", failedMsg.getVerificationOutcome());
        assertTrue(keyStore.contains(failedMsg.getEphemeralKeyId() + "-priv"));
        assertTrue(auditLogRepository.findAllByOrderBySeqNumberDesc().stream()
                .anyMatch(a -> "SECURE_MESSAGE_REJECTED".equals(a.getAction()) && gcmFailMsgId.equals(a.getResource())));

        // 3. Signature failure on clean message does NOT erase ephemeral key, and audit is persisted
        String sigFailMsgId = "reg-sigfail-" + UUID.randomUUID().toString().substring(0, 8);
        mockMvc.perform(post("/api/v1/messages")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "recipientUsername", "bob",
                                "plaintext", "Signature rejection test",
                                "customMessageId", sigFailMsgId
                        ))))
                .andExpect(status().isOk());

        String fakeCt = Base64.getEncoder().encodeToString("tampered-bytes".getBytes(StandardCharsets.UTF_8));
        mockMvc.perform(post("/api/v1/messages/" + sigFailMsgId + "/receive")
                        .header("Authorization", "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("overrideCiphertextB64", fakeCt))))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("SIGNATURE_INVALID"));

        SecureMessageEntity sigFailedMsg = messageRepository.findByMessageId(sigFailMsgId).orElseThrow();
        assertTrue(keyStore.contains(sigFailedMsg.getEphemeralKeyId() + "-priv"));
        assertTrue(auditLogService.verifyChainReadOnly().valid());
    }

    @Test
    void sessionAndMessageListingAndCloseSessionEnforceOwnershipAndScoping() throws Exception {
        // Alice opens a session; Alice & Bob create isolated messages
        MvcResult aliceSessRes = mockMvc.perform(post("/api/v1/sessions/open")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andReturn();
        String aliceSessId = objectMapper.readTree(aliceSessRes.getResponse().getContentAsString()).get("sessionId").asText();

        // Charlie cannot close Alice's session
        mockMvc.perform(post("/api/v1/sessions/" + aliceSessId + "/close")
                        .header("Authorization", "Bearer " + charlieToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("SESSION_PEER_MISMATCH"));

        // Alice sends secret message to Bob; Charlie must NOT see it in GET /api/v1/messages or Alice's session in GET /api/v1/sessions
        String privMsgId = "reg-scope-" + UUID.randomUUID().toString().substring(0, 8);
        mockMvc.perform(post("/api/v1/messages")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "recipientUsername", "bob",
                                "plaintext", "Private channel body",
                                "customMessageId", privMsgId
                        ))))
                .andExpect(status().isOk());

        String charlieMsgs = mockMvc.perform(get("/api/v1/messages")
                        .header("Authorization", "Bearer " + charlieToken))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertFalse(charlieMsgs.contains(privMsgId));

        String bobMsgs = mockMvc.perform(get("/api/v1/messages")
                        .header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertTrue(bobMsgs.contains(privMsgId));

        String charlieSessions = mockMvc.perform(get("/api/v1/sessions")
                        .header("Authorization", "Bearer " + charlieToken))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertFalse(charlieSessions.contains(aliceSessId));

        // Admin retains full visibility
        String adminSessions = mockMvc.perform(get("/api/v1/sessions")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertTrue(adminSessions.contains(aliceSessId));

        // Alice (owner) can close her own session cleanly
        mockMvc.perform(post("/api/v1/sessions/" + aliceSessId + "/close")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CLOSED"));
    }

    @Test
    void deviceRevocationInvalidatesJwtBlocksNonAdminSelfEnrollAndJwtUsesDbAuthorities() throws Exception {
        // Create isolated user with ADMIN privileges initially, mint JWT, then demote to USER in DB -> old JWT must lose ADMIN privileges!
        UserEntity demotable = new UserEntity();
        demotable.setUsername("sec-demote-user");
        demotable.setDisplayName("Demotable User");
        demotable.setEmail("sec-demote@trustguard.local");
        demotable.setRole("ADMIN");
        demotable.setPasswordHash(passwordEncoder.encode("Pass!2026"));
        demotable.setActive(true);
        userRepository.save(demotable);

        String preDemotionJwt = login("sec-demote-user", "Pass!2026");

        demotable.setRole("USER");
        userRepository.save(demotable);

        // Even though JWT still contains "role":"ADMIN", JwtAuthenticationFilter loads DB role "USER" -> ADMIN endpoint rejects!
        mockMvc.perform(post("/api/v1/keys/prepare")
                        .header("Authorization", "Bearer " + preDemotionJwt)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());

        // Create isolated regular user with an enrolled device
        UserEntity target = new UserEntity();
        target.setUsername("sec-revoke-user");
        target.setDisplayName("Revoke User");
        target.setEmail("sec-revoke@trustguard.local");
        target.setRole("USER");
        target.setPasswordHash(passwordEncoder.encode("Pass!2026"));
        target.setActive(true);
        target = userRepository.save(target);

        MvcResult devRes = mockMvc.perform(post("/api/v1/devices/enrol")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "ownerUsername", "sec-revoke-user",
                                "deviceName", "Sec Laptop"
                        ))))
                .andExpect(status().isOk())
                .andReturn();
        long devId = objectMapper.readTree(devRes.getResponse().getContentAsString()).get("id").asLong();

        String oldUserJwt = login("sec-revoke-user", "Pass!2026");

        // Admin revokes user's device -> tokenVersion increments, old JWT immediately rejected with 401
        mockMvc.perform(post("/api/v1/devices/" + devId + "/revoke")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"Stolen device\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + oldUserJwt))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/devices/enrol")
                        .header("Authorization", "Bearer " + oldUserJwt)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"deviceName\":\"Sneaky Bypass\"}"))
                .andExpect(status().isUnauthorized());

        // Even with a fresh login JWT, a revoked non-admin user CANNOT self-enroll without ADMIN approval
        String freshUserJwt = login("sec-revoke-user", "Pass!2026");
        mockMvc.perform(post("/api/v1/devices/enrol")
                        .header("Authorization", "Bearer " + freshUserJwt)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"deviceName\":\"Self Mint After Revoke\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ADMIN_APPROVAL_REQUIRED"));
    }

    @Test
    void multiAliasKeyIsolationPreservesPrimaryDekAndAvoidsNonUniqueQueries() throws Exception {
        byte[] primaryV1DekBefore = keyManagementService.loadDek(keyManagementService.getActiveCommittedKey());

        // Prepare, acknowledge, and commit a second alias starting at v1
        MvcResult prepRes = mockMvc.perform(post("/api/v1/keys/prepare")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyAlias\":\"secondary-archive-key\",\"gracePeriodSeconds\":60}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyAlias").value("secondary-archive-key"))
                .andExpect(jsonPath("$.versionNumber").value(1))
                .andReturn();
        long secKeyId = objectMapper.readTree(prepRes.getResponse().getContentAsString()).get("id").asLong();

        mockMvc.perform(post("/api/v1/keys/" + secKeyId + "/acknowledge")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACKNOWLEDGED"));

        mockMvc.perform(post("/api/v1/keys/" + secKeyId + "/commit")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("COMMITTED"));

        // Primary v1 DEK MUST NOT be overwritten, and validateKeyUsage cleanly isolates both aliases at v1 without non-unique query errors
        byte[] primaryV1DekAfter = keyManagementService.loadDek(keyManagementService.getActiveCommittedKey());
        assertArrayEquals(primaryV1DekBefore, primaryV1DekAfter);
        assertEquals("trustguard-data-key", keyManagementService.validateKeyUsage("trustguard-data-key", 1, Instant.now()).getKeyAlias());
        assertEquals("secondary-archive-key", keyManagementService.validateKeyUsage("secondary-archive-key", 1, Instant.now()).getKeyAlias());

        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "brief-alice",
                                "action", "read",
                                "requestedKeyVersion", 1
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"))
                .andExpect(jsonPath("$.body", containsString("Synthetic Brief Body")));
    }

    @Test
    void backupDetectsRecomputedSha256WithoutHmacAndRestoresResourcesPreservingHigherKeyVersion() throws Exception {
        // 1. Create verified backup while primary key is v1
        MvcResult bakRes = mockMvc.perform(post("/api/v1/backups/create")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andReturn();
        String backupId = objectMapper.readTree(bakRes.getResponse().getContentAsString()).get("backupId").asText();

        // 2. Simulate DB-level attacker rewriting BOTH payloadSnapshotJson and unkeyed checksumSha256 without HMAC key
        BackupRecordEntity forged = backupRecordRepository.findByBackupId(backupId).orElseThrow();
        String originalPayload = forged.getPayloadSnapshotJson();
        String originalChecksum = forged.getChecksumSha256();
        String tamperedPayload = originalPayload.replace("\"REVOKED\"", "\"ACTIVE\"") + " ";
        forged.setPayloadSnapshotJson(tamperedPayload);
        forged.setChecksumSha256(HashUtil.sha256Hex(tamperedPayload));
        backupRecordRepository.save(forged);

        long bakRejectAuditsBefore = auditLogRepository.findAllByOrderBySeqNumberDesc().stream()
                .filter(a -> "BACKUP_RESTORE_REJECTED".equals(a.getAction()))
                .count();

        mockMvc.perform(post("/api/v1/backups/" + backupId + "/restore")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("BACKUP_CORRUPTED"));

        long bakRejectAuditsAfter = auditLogRepository.findAllByOrderBySeqNumberDesc().stream()
                .filter(a -> "BACKUP_RESTORE_REJECTED".equals(a.getAction()))
                .count();
        assertEquals(bakRejectAuditsBefore + 1, bakRejectAuditsAfter);
        BackupRecordEntity afterReject = backupRecordRepository.findByBackupId(backupId).orElseThrow();
        assertEquals("CORRUPTED", afterReject.getVerificationStatus());
        assertEquals("REJECTED", afterReject.getRestoreStatus());

        // Restore original clean payload/checksum for part 3 (still has valid original HMAC!)
        afterReject.setPayloadSnapshotJson(originalPayload);
        afterReject.setChecksumSha256(originalChecksum);
        backupRecordRepository.save(afterReject);

        // 3. Rotate primary key v1 -> v2, corrupt brief-alice's DB metadata + ciphertext, then restore v1 backup!
        MvcResult rotPrep = mockMvc.perform(post("/api/v1/keys/prepare")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyAlias\":\"trustguard-data-key\",\"gracePeriodSeconds\":60}"))
                .andExpect(status().isOk())
                .andReturn();
        long v2Id = objectMapper.readTree(rotPrep.getResponse().getContentAsString()).get("id").asLong();
        int v2Num = objectMapper.readTree(rotPrep.getResponse().getContentAsString()).get("versionNumber").asInt();

        mockMvc.perform(post("/api/v1/keys/" + v2Id + "/acknowledge").header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/v1/keys/" + v2Id + "/commit").header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        ResourceEntity brief = resourceRepository.findByResourceKey("brief-alice").orElseThrow();
        brief.setAllowedServices("corrupted-only");
        brief.setContentCiphertextB64(Base64.getEncoder().encodeToString("corrupt-ciphertext".getBytes(StandardCharsets.UTF_8)));
        resourceRepository.save(brief);

        mockMvc.perform(post("/api/v1/backups/" + backupId + "/restore")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.restoreStatus").value("RESTORED"));

        // Resource metadata + original plaintext MUST be restored AND higher committed key v2 MUST be preserved!
        ResourceEntity restoredBrief = resourceRepository.findByResourceKey("brief-alice").orElseThrow();
        assertEquals("portal,catalog,vault", restoredBrief.getAllowedServices());
        assertEquals(v2Num, restoredBrief.getActiveKeyVersion().getVersionNumber());

        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "brief-alice",
                                "action", "read"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"))
                .andExpect(jsonPath("$.keyVersionUsed").value(v2Num))
                .andExpect(jsonPath("$.body", containsString("Synthetic Brief Body")));
    }

    @Test
    void auditActorBoundedToColumnLengthAndCorsRejectsWildcardOrigins() throws Exception {
        // Long simulated actor produces admin[sim:...] > 64 chars without SQL truncation error
        UserEntity longUser = new UserEntity();
        String longUsername = "u".repeat(60);
        longUser.setUsername(longUsername);
        longUser.setDisplayName("Long Username");
        longUser.setEmail("longuser@trustguard.local");
        longUser.setRole("USER");
        longUser.setPasswordHash(passwordEncoder.encode("Pass!2026"));
        longUser.setActive(true);
        userRepository.save(longUser);

        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "simulatedActor", longUsername,
                                "simulationMode", true,
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "brief-alice",
                                "action", "read"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("DENY"));

        AuditLogEntity latestAudit = auditLogRepository.findTopByOrderBySeqNumberDesc().orElseThrow();
        assertTrue(latestAudit.getActor().length() <= 64);

        // Explicit CORS allows configured origin and blocks arbitrary vercel subdomain wildcard
        mockMvc.perform(options("/api/v1/health")
                        .header("Origin", "https://trust-guard-mocha.vercel.app")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "https://trust-guard-mocha.vercel.app"));

        mockMvc.perform(options("/api/v1/health")
                        .header("Origin", "https://evil-attacker.vercel.app")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    @Test
    void nonAdminReadEndpointsAreScopedAndAdminTriggersRequireAdminRole() throws Exception {
        // Trigger an access event for alice and one for bob
        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "brief-alice",
                                "action", "read"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"));

        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "key-bob",
                                "action", "read"
                        ))))
                .andExpect(status().isOk());

        // /resources: alice only sees alice-owned resources; admin sees all
        JsonNode aliceResources = objectMapper.readTree(
                mockMvc.perform(get("/api/v1/resources").header("Authorization", "Bearer " + aliceToken))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
        assertTrue(aliceResources.isArray() && aliceResources.size() >= 1);
        for (JsonNode r : aliceResources) {
            assertEquals("alice", r.get("ownerUsername").asText());
        }

        JsonNode adminResources = objectMapper.readTree(
                mockMvc.perform(get("/api/v1/resources").header("Authorization", "Bearer " + adminToken))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
        assertTrue(adminResources.size() > aliceResources.size());

        // /access/events: alice only sees alice events; admin sees both alice & bob
        JsonNode aliceEvents = objectMapper.readTree(
                mockMvc.perform(get("/api/v1/access/events").header("Authorization", "Bearer " + aliceToken))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
        assertTrue(aliceEvents.isArray() && aliceEvents.size() >= 1);
        for (JsonNode ev : aliceEvents) {
            boolean matchesAlice = "alice".equals(ev.get("actor").asText())
                    || "alice".equals(ev.get("authenticatedPrincipal").asText());
            assertTrue(matchesAlice);
        }

        JsonNode adminEvents = objectMapper.readTree(
                mockMvc.perform(get("/api/v1/access/events").header("Authorization", "Bearer " + adminToken))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
        boolean adminSeesBob = false;
        for (JsonNode ev : adminEvents) {
            if ("bob".equals(ev.get("actor").asText())) {
                adminSeesBob = true;
                break;
            }
        }
        assertTrue(adminSeesBob);

        // /devices: alice only sees alice devices; admin sees all owners
        JsonNode aliceDevices = objectMapper.readTree(
                mockMvc.perform(get("/api/v1/devices").header("Authorization", "Bearer " + aliceToken))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
        assertTrue(aliceDevices.isArray() && aliceDevices.size() >= 1);
        for (JsonNode d : aliceDevices) {
            assertEquals("alice", d.get("ownerUsername").asText());
        }

        JsonNode adminDevices = objectMapper.readTree(
                mockMvc.perform(get("/api/v1/devices").header("Authorization", "Bearer " + adminToken))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
        assertTrue(adminDevices.size() > aliceDevices.size());

        // /users: alice only sees herself; admin sees all; /users/recipients exposes only username + displayName
        JsonNode aliceUsers = objectMapper.readTree(
                mockMvc.perform(get("/api/v1/users").header("Authorization", "Bearer " + aliceToken))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
        assertEquals(1, aliceUsers.size());
        assertEquals("alice", aliceUsers.get(0).get("username").asText());

        JsonNode adminUsers = objectMapper.readTree(
                mockMvc.perform(get("/api/v1/users").header("Authorization", "Bearer " + adminToken))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
        assertTrue(adminUsers.size() >= 4);

        JsonNode recipients = objectMapper.readTree(
                mockMvc.perform(get("/api/v1/users/recipients").header("Authorization", "Bearer " + aliceToken))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
        assertTrue(recipients.size() >= 4);
        for (JsonNode r : recipients) {
            assertTrue(r.hasNonNull("username"));
            assertTrue(r.hasNonNull("displayName"));
            assertFalse(r.has("email"));
            assertFalse(r.has("role"));
        }

        // Admin-only mutation triggers vs read-only detection snapshot
        mockMvc.perform(post("/api/v1/sessions/run-tests")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));

        mockMvc.perform(post("/api/v1/detection/evaluate")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));

        mockMvc.perform(get("/api/v1/detection/latest")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEventsProcessed").value(22));

        mockMvc.perform(post("/api/v1/detection/evaluate")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEventsProcessed").value(22));
    }

    @Test
    void loginRateLimitingBlocksRepeatedFailuresAndLogoutInvalidatesJwtImmediately() throws Exception {
        authRateLimiter.clearAll();
        try {
            // 1. Per-username brute-force rate limit (5 failures -> 6th returns 429 even with valid password)
            for (int i = 0; i < 5; i++) {
                mockMvc.perform(post("/api/v1/auth/login")
                                .with(req -> {
                                    req.setRemoteAddr("198.51.100.10");
                                    return req;
                                })
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(Map.of(
                                        "username", "alice",
                                        "password", "WrongPassword!"
                                ))))
                        .andExpect(status().isUnauthorized())
                        .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
            }

            mockMvc.perform(post("/api/v1/auth/login")
                            .with(req -> {
                                req.setRemoteAddr("198.51.100.10");
                                return req;
                            })
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(Map.of(
                                    "username", "alice",
                                    "password", "TrustGuard!Demo2026"
                            ))))
                    .andExpect(status().isTooManyRequests())
                    .andExpect(jsonPath("$.code").value("AUTH_RATE_LIMITED"));

            // 2. Per-IP distributed username spraying threshold (25 failures across usernames from one IP -> 26th returns 429)
            for (int i = 0; i < 25; i++) {
                mockMvc.perform(post("/api/v1/auth/login")
                                .with(req -> {
                                    req.setRemoteAddr("198.51.100.20");
                                    return req;
                                })
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(Map.of(
                                        "username", "spray-user-" + i,
                                        "password", "WrongPassword!"
                                ))))
                        .andExpect(status().isUnauthorized());
            }

            mockMvc.perform(post("/api/v1/auth/login")
                            .with(req -> {
                                req.setRemoteAddr("198.51.100.20");
                                return req;
                            })
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(Map.of(
                                    "username", "bob",
                                    "password", "TrustGuard!Demo2026"
                            ))))
                    .andExpect(status().isTooManyRequests())
                    .andExpect(jsonPath("$.code").value("AUTH_RATE_LIMITED"));
        } finally {
            authRateLimiter.clearAll();
        }

        // 3. Logout invalidates active JWT and emits AUTH_SIGN_OUT audit log
        mockMvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.loggedOut").value(true))
                .andExpect(jsonPath("$.username").value("bob"));

        AuditLogEntity latestAudit = auditLogRepository.findTopByOrderBySeqNumberDesc().orElseThrow();
        assertEquals("AUTH_SIGN_OUT", latestAudit.getAction());
        assertEquals("bob", latestAudit.getActor());

        mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }

    @Test
    void protectedReadValidatesInputsBeforePersistingAccessEventsOrAuditLogs() throws Exception {
        long eventsBefore = accessEventRepository.count();
        long auditsBefore = auditLogRepository.count();

        // Null challenge
        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "brief-alice",
                                "action", "read",
                                "protectedRead", true,
                                "publicKeyB64", Base64.getEncoder().encodeToString(new byte[PostQuantumCryptoService.ML_KEM_768_PUBLIC_KEY_BYTES])
                        ))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"));

        // Invalid Base64
        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "brief-alice",
                                "action", "read",
                                "protectedRead", true,
                                "challenge", "chk-invalid-b64",
                                "publicKeyB64", "%%%not-base64%%%"
                        ))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"));

        // Wrong decoded ML-KEM-768 public key byte length
        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "brief-alice",
                                "action", "read",
                                "protectedRead", true,
                                "challenge", "chk-wrong-len",
                                "publicKeyB64", Base64.getEncoder().encodeToString(new byte[32])
                        ))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"));

        assertEquals(eventsBefore, accessEventRepository.count());
        assertEquals(auditsBefore, auditLogRepository.count());
    }

    @Test
    void nonDevStartupGuardsRejectWeakJwtSecretAndDefaultDemoSeedCredentials() {
        MockEnvironment prodEnv = new MockEnvironment().withProperty("spring.profiles.active", "prod");
        prodEnv.setActiveProfiles("prod");

        JwtService missingSecretJwt = new JwtService(keyStore, prodEnv, "", 3600);
        assertThrows(IllegalStateException.class, missingSecretJwt::init);

        JwtService shortSecretJwt = new JwtService(keyStore, prodEnv, "too-short-secret-key-under-32b", 3600);
        assertThrows(IllegalStateException.class, shortSecretJwt::init);

        JwtService strongSecretJwt = new JwtService(keyStore, prodEnv, "S".repeat(32), 3600);
        assertDoesNotThrow(strongSecretJwt::init);

        DataInitializer unsafeProdSeeder = new DataInitializer(
                userRepository, deviceRepository, keyVersionRepository, nodeRepository, ackRepository,
                resourceRepository, rolePermissionRepository, passwordEncoder, cryptoService, keyStore,
                auditLogService, detectionService, prodEnv, true, DataInitializer.DEFAULT_DEMO_PASSWORD
        );
        assertThrows(IllegalStateException.class, () -> unsafeProdSeeder.run(new DefaultApplicationArguments()));

        DataInitializer disabledProdSeeder = new DataInitializer(
                userRepository, deviceRepository, keyVersionRepository, nodeRepository, ackRepository,
                resourceRepository, rolePermissionRepository, passwordEncoder, cryptoService, keyStore,
                auditLogService, detectionService, prodEnv, false, DataInitializer.DEFAULT_DEMO_PASSWORD
        );
        assertDoesNotThrow(() -> disabledProdSeeder.run(new DefaultApplicationArguments()));
    }

    @Test
    void concurrentAuditAppendsInsideFullPoolOuterTransactionsPreserveChainWithoutDeadlock() throws Exception {
        // Default HikariCP maxPoolSize=10; pin all 10 primary connections across 10 outer transactions simultaneously
        // while each thread appends to AuditLogService, proving isolated audit pool avoids pool exhaustion deadlock.
        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch allAppended = new CountDownLatch(threadCount);
        TransactionTemplate outerTx = new TransactionTemplate(transactionManager);
        long baselineCount = auditLogRepository.count();

        try {
            List<Future<Long>> futures = new ArrayList<>();
            for (int i = 0; i < threadCount; i++) {
                final int idx = i;
                futures.add(executor.submit(() -> outerTx.execute(status -> {
                    // Hold an active JDBC connection in the outer transaction by touching the DB first
                    userRepository.count();
                    AuditLogEntity appended = auditLogService.appendEvent(
                            "concurrent-worker-" + idx,
                            "CONCURRENCY_AUDIT_TEST",
                            "audit-chain",
                            "Parallel append #" + idx + " under full primary pool occupancy"
                    );
                    allAppended.countDown();
                    try {
                        assertTrue(allAppended.await(15, TimeUnit.SECONDS), "Outer TX threads deadlocked waiting on audit pool");
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException(e);
                    }
                    return appended.getSeqNumber();
                })));
            }

            List<Long> seqs = new ArrayList<>();
            for (Future<Long> f : futures) {
                seqs.add(f.get(20, TimeUnit.SECONDS));
            }
            assertEquals(threadCount, seqs.stream().distinct().count());
            assertEquals(baselineCount + threadCount, auditLogRepository.count());
            assertTrue(auditLogService.verifyChainReadOnly().valid());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void httpResponsesIncludeStrictSecurityHeaders() throws Exception {
        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Cache-Control", "no-store"));

        mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Cache-Control", "no-store"));

        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Cache-Control", "no-store"));
    }
}
