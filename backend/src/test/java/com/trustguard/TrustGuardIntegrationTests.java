package com.trustguard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.crypto.PostQuantumCryptoService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TrustGuardIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PostQuantumCryptoService cryptoService;

    private String adminToken;
    private String aliceToken;
    private String bobToken;

    @BeforeEach
    void authenticateDemoUsers() throws Exception {
        adminToken = login("admin", "TrustGuard!Demo2026");
        aliceToken = login("alice", "TrustGuard!Demo2026");
        bobToken = login("bob", "TrustGuard!Demo2026");
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
    void unauthenticatedRejectedAndNonAdminImpersonationBlocked() throws Exception {
        mockMvc.perform(get("/api/v1/dashboard"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "simulatedActor", "bob",
                                "simulationMode", true,
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "ledger-bob",
                                "action", "read"
                        ))))
                .andExpect(status().isForbidden());
    }

    @Test
    void unauthorizedAccessDeniesWithoutContentDisclosureAndProtectedReadVerifies() throws Exception {
        // Alice cannot read Bob's ledger
        MvcResult denied = mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "ledger-bob",
                                "action", "read"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andReturn();
        JsonNode deniedJson = objectMapper.readTree(denied.getResponse().getContentAsString());
        assertTrue(deniedJson.get("body").isNull());
        assertFalse(denied.getResponse().getContentAsString().contains("Balance invariants"));

        // Alice protected_read on her own resource with real ML-KEM-768
        PostQuantumCryptoService.RawKeyPair ephemeral = cryptoService.generateMlKem768KeyPair();
        String pkB64 = Base64.getEncoder().encodeToString(ephemeral.publicKey());
        String challenge = "chal-" + UUID.randomUUID();

        MvcResult allowed = mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "brief-alice",
                                "action", "read",
                                "protectedRead", true,
                                "challenge", challenge,
                                "publicKeyB64", pkB64
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"))
                .andExpect(jsonPath("$.ciphertextB64").isNotEmpty())
                .andExpect(jsonPath("$.proofHex").isNotEmpty())
                .andReturn();

        JsonNode allowedJson = objectMapper.readTree(allowed.getResponse().getContentAsString());
        assertTrue(allowedJson.get("body").isNull());
        byte[] ss = cryptoService.decapsulateMlKem768(
                ephemeral.privateKey(),
                Base64.getDecoder().decode(allowedJson.get("ciphertextB64").asText())
        );
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(ss, "HmacSHA256"));
        String expectedProof = HexFormat.of().formatHex(mac.doFinal(
                (challenge + "Synthetic Brief Body: ML-KEM-768 rollout milestones for Alice.").getBytes(StandardCharsets.UTF_8)
        ));
        assertEquals(expectedProof, allowedJson.get("proofHex").asText());
    }

    @Test
    void deviceRevocationPropagatesToAllNodesPreservesPeerAndAllowsReplacement() throws Exception {
        // Enroll temporary device for Charlie and revoke it
        MvcResult enrolledRes = mockMvc.perform(post("/api/v1/devices/enrol")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "ownerUsername", "charlie",
                                "deviceName", "Charlie Lost Tablet"
                        ))))
                .andExpect(status().isOk())
                .andReturn();
        long charlieDevId = objectMapper.readTree(enrolledRes.getResponse().getContentAsString()).get("id").asLong();

        mockMvc.perform(post("/api/v1/devices/" + charlieDevId + "/revoke")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"Lost on commute\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nodesEnforced").value(3))
                .andExpect(jsonPath("$.otherUsersPreserved").value(true));

        // Revoked device denied across node-beta
        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "simulatedActor", "charlie",
                                "simulationMode", true,
                                "deviceId", charlieDevId,
                                "sourceService", "portal",
                                "targetService", "catalog",
                                "resourceKey", "compliance-charlie",
                                "action", "read",
                                "nodeCode", "node-beta"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.reason", containsString("REVOKED_DEVICE")));

        // Peer Bob still allowed
        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "ledger-bob",
                                "action", "read"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"));

        // Owner can enroll replacement device
        mockMvc.perform(post("/api/v1/devices/enrol")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "ownerUsername", "charlie",
                                "deviceName", "Charlie Replacement Phone",
                                "replacesDeviceId", charlieDevId
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void keyRotationRequiresQuorumAndRejectsOldKeyAfterCutoff() throws Exception {
        // Prepare new key with 0s grace so old v1 hits immediate cutoff on commit
        MvcResult prepRes = mockMvc.perform(post("/api/v1/keys/prepare")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyAlias\":\"trustguard-data-key\",\"gracePeriodSeconds\":0}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DISTRIBUTED"))
                .andReturn();
        long newKeyId = objectMapper.readTree(prepRes.getResponse().getContentAsString()).get("id").asLong();
        int newVersion = objectMapper.readTree(prepRes.getResponse().getContentAsString()).get("versionNumber").asInt();

        // Commit before acknowledgements MUST fail
        mockMvc.perform(post("/api/v1/keys/" + newKeyId + "/commit")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ACK_QUORUM_NOT_MET"));

        // Simulate failure on node 3 -> acknowledge leaves node failed and commit blocked
        MvcResult nodesRes = mockMvc.perform(get("/api/v1/nodes")
                        .header("Authorization", "Bearer " + adminToken))
                .andReturn();
        long thirdNodeId = objectMapper.readTree(nodesRes.getResponse().getContentAsString()).get(2).get("id").asLong();

        mockMvc.perform(post("/api/v1/nodes/" + thirdNodeId + "/toggle-failure")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"simulateAckFailure\":true}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/keys/" + newKeyId + "/acknowledge")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DISTRIBUTED"));

        mockMvc.perform(post("/api/v1/keys/" + newKeyId + "/commit")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isConflict());

        // Recover node 3 -> acknowledge -> commit succeeds
        mockMvc.perform(post("/api/v1/nodes/" + thirdNodeId + "/toggle-failure")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"simulateAckFailure\":false}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/keys/" + newKeyId + "/acknowledge")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACKNOWLEDGED"));

        mockMvc.perform(post("/api/v1/keys/" + newKeyId + "/commit")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("COMMITTED"));

        // Old key v1 rejected after cutoff
        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "ledger-bob",
                                "action", "read",
                                "requestedKeyVersion", 1
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.reason", containsString("cutoff")));

        // New committed key version succeeds
        mockMvc.perform(post("/api/v1/access/check")
                        .header("Authorization", "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "sourceService", "portal",
                                "targetService", "vault",
                                "resourceKey", "ledger-bob",
                                "action", "read",
                                "requestedKeyVersion", newVersion
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"));
    }

    @Test
    void auditTamperDetectionAndRecovery() throws Exception {
        mockMvc.perform(post("/api/v1/audit/verify")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));

        mockMvc.perform(post("/api/v1/audit/simulate-tamper")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"seqNumber\":1}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.firstMismatchSeq").value(1));

        mockMvc.perform(post("/api/v1/audit/revert-tamper")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void secureMessagingReplayTamperAndRecipientRejectionAndBackupCorruption() throws Exception {
        // Run repeatable session & delivery suite
        mockMvc.perform(post("/api/v1/sessions/run-tests")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].status", everyItem(equalTo("MEASURED_PASS"))));

        // Backup create -> verify -> corrupt -> restore rejected
        MvcResult bakRes = mockMvc.perform(post("/api/v1/backups/create")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verificationStatus").value("VERIFIED"))
                .andReturn();
        String backupId = objectMapper.readTree(bakRes.getResponse().getContentAsString()).get("backupId").asText();

        mockMvc.perform(post("/api/v1/backups/" + backupId + "/restore")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.restoreStatus").value("RESTORED"));

        mockMvc.perform(post("/api/v1/backups/" + backupId + "/simulate-corruption")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verificationStatus").value("CORRUPTED"));

        mockMvc.perform(post("/api/v1/backups/" + backupId + "/restore")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("BACKUP_CORRUPTED"));

        // Re-running deterministic detection evaluation must remain idempotent
        mockMvc.perform(post("/api/v1/detection/evaluate")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEventsProcessed").value(22))
                .andExpect(jsonPath("$.labelsUsedInDetectionLogic").value(false))
                .andExpect(jsonPath("$.postDetectionEvaluation.exactLabelMatches").value(22));
    }
}
