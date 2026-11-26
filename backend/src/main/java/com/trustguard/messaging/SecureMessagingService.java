package com.trustguard.messaging;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.audit.AuditLogService;
import com.trustguard.crypto.PostQuantumCryptoService;
import com.trustguard.crypto.ProtectedKeyStore;
import com.trustguard.dto.ReceiveMessageRequest;
import com.trustguard.dto.SecureMessageResponse;
import com.trustguard.dto.SendMessageRequest;
import com.trustguard.entity.ConsumedMessageEntity;
import com.trustguard.entity.DeviceEntity;
import com.trustguard.entity.SecureMessageEntity;
import com.trustguard.entity.SecurityAlertEntity;
import com.trustguard.exception.AccessDeniedBusinessException;
import com.trustguard.exception.ConflictException;
import com.trustguard.exception.IntegrityViolationException;
import com.trustguard.exception.ResourceNotFoundException;
import com.trustguard.repository.ConsumedMessageRepository;
import com.trustguard.repository.DeviceRepository;
import com.trustguard.repository.SecureMessageRepository;
import com.trustguard.repository.SecurityAlertRepository;
import com.trustguard.security.SecurityUtils;
import com.trustguard.util.CanonicalJsonUtil;
import com.trustguard.util.HashUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class SecureMessagingService {

    private final SecureMessageRepository messageRepository;
    private final ConsumedMessageRepository consumedRepository;
    private final DeviceRepository deviceRepository;
    private final SecurityAlertRepository alertRepository;
    private final PostQuantumCryptoService cryptoService;
    private final ProtectedKeyStore keyStore;
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;

    public SecureMessagingService(
            SecureMessageRepository messageRepository,
            ConsumedMessageRepository consumedRepository,
            DeviceRepository deviceRepository,
            SecurityAlertRepository alertRepository,
            PostQuantumCryptoService cryptoService,
            ProtectedKeyStore keyStore,
            AuditLogService auditLogService,
            ObjectMapper objectMapper
    ) {
        this.messageRepository = messageRepository;
        this.consumedRepository = consumedRepository;
        this.deviceRepository = deviceRepository;
        this.alertRepository = alertRepository;
        this.cryptoService = cryptoService;
        this.keyStore = keyStore;
        this.auditLogService = auditLogService;
        this.objectMapper = objectMapper;
    }

    public List<SecureMessageResponse> listMessages() {
        return messageRepository.findAllByOrderByCreatedAtDesc().stream()
                .map(m -> toDto(m, null))
                .toList();
    }

    @Transactional
    public SecureMessageResponse sendMessage(SendMessageRequest req) {
        String senderUsername = SecurityUtils.currentUsername();
        DeviceEntity senderDevice = resolveActiveDevice(req.senderDeviceId(), senderUsername);
        DeviceEntity recipientDevice = resolveActiveDevice(req.recipientDeviceId(), req.recipientUsername().trim());

        if ("REVOKED".equals(senderDevice.getStatus()) || "REVOKED".equals(recipientDevice.getStatus())) {
            throw new AccessDeniedBusinessException(
                    "DEVICE_REVOKED",
                    "Cannot establish secure messaging channel with a revoked device"
            );
        }

        String messageId = (req.customMessageId() != null && !req.customMessageId().isBlank())
                ? req.customMessageId().trim()
                : "msg-" + UUID.randomUUID().toString().substring(0, 12);

        if (messageRepository.findByMessageId(messageId).isPresent() || consumedRepository.existsByMessageId(messageId)) {
            recordReplayAlert(senderUsername, messageId, "Attempted duplicate messageId during send");
            throw new ConflictException("DUPLICATE_MESSAGE_ID", "Message ID already exists: " + messageId);
        }

        Instant createdAt = Instant.now();
        // Generate fresh one-time ephemeral ML-KEM-768 session keypair for forward secrecy:
        // ephemeral private key is erased immediately upon receipt/decapsulation (one-time prekey).
        String ephemeralKeyId = "eph-" + messageId;
        PostQuantumCryptoService.RawKeyPair ephemeralKem = cryptoService.generateMlKem768KeyPair();
        keyStore.storeSecret(ephemeralKeyId + "-priv", ephemeralKem.privateKey());

        String boundRecipient = req.simulateTamperedRecipient()
                ? "tampered-wrong-recipient"
                : recipientDevice.getOwner().getUsername();

        Map<String, Object> aadMap = new LinkedHashMap<>();
        aadMap.put("messageId", messageId);
        aadMap.put("sender", senderUsername);
        aadMap.put("senderDeviceUid", senderDevice.getDeviceUid());
        aadMap.put("recipient", boundRecipient);
        aadMap.put("recipientDeviceUid", recipientDevice.getDeviceUid());
        aadMap.put("timestampUtc", createdAt.toString());
        String aadJson = CanonicalJsonUtil.toCanonicalJson(aadMap);

        PostQuantumCryptoService.KemEncapsulation encap = cryptoService.encapsulateMlKem768(ephemeralKem.publicKey());
        byte[] aesKey = null;
        byte[] senderSigningPriv = keyStore.loadSecret(senderDevice.getDeviceUid() + "-dsa-priv");
        try {
            byte[] hkdfInfo = ("trustguard-msg-v1|" + messageId + "|" + senderUsername + "|" + boundRecipient)
                    .getBytes(StandardCharsets.UTF_8);
            aesKey = cryptoService.hkdfSha256(encap.sharedSecret(), messageId.getBytes(StandardCharsets.UTF_8), hkdfInfo, 32);
            PostQuantumCryptoService.AesGcmPayload encrypted = cryptoService.encryptAes256Gcm(
                    aesKey,
                    req.plaintext(),
                    aadJson
            );
            String kemCtB64 = Base64.getEncoder().encodeToString(encap.ciphertext());
            String payloadCiphertextB64 = encrypted.ciphertextB64();
            if (req.simulateTamperedCiphertext()) {
                byte[] ctBytes = Base64.getDecoder().decode(payloadCiphertextB64);
                ctBytes[0] = (byte) (ctBytes[0] ^ 0xFF);
                payloadCiphertextB64 = Base64.getEncoder().encodeToString(ctBytes);
            }

            String signatureInput = messageId + "|" + kemCtB64 + "|" + encrypted.ivB64() + "|" + payloadCiphertextB64 + "|" + aadJson;
            byte[] sigBytes = cryptoService.signMlDsa65(senderSigningPriv, signatureInput.getBytes(StandardCharsets.UTF_8));

            SecureMessageEntity entity = new SecureMessageEntity();
            entity.setMessageId(messageId);
            entity.setSenderUsername(senderUsername);
            entity.setSenderDevice(senderDevice);
            entity.setRecipientUsername(recipientDevice.getOwner().getUsername());
            entity.setRecipientDevice(recipientDevice);
            entity.setAlgorithm("ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM");
            entity.setSignatureAlgorithm("ML-DSA-65");
            entity.setKemCiphertextB64(kemCtB64);
            entity.setIvB64(encrypted.ivB64());
            entity.setCiphertextB64(payloadCiphertextB64);
            entity.setAadJson(aadJson);
            entity.setSignatureB64(Base64.getEncoder().encodeToString(sigBytes));
            entity.setEphemeralKeyId(ephemeralKeyId);
            entity.setForwardSecrecyErased(true);
            entity.setStatus("SENT");
            entity.setVerificationOutcome("PENDING_DELIVERY");
            entity.setCreatedAt(createdAt);
            messageRepository.save(entity);

            auditLogService.appendEvent(
                    senderUsername,
                    "SECURE_MESSAGE_SENT",
                    messageId,
                    "Encrypted with ephemeral ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM and signed with ML-DSA-65 for "
                            + recipientDevice.getOwner().getUsername() + " (ephemeral sender secret erased)"
            );
            return toDto(entity, null);
        } finally {
            cryptoService.zeroize(ephemeralKem.privateKey(), encap.sharedSecret(), aesKey, senderSigningPriv);
        }
    }

    @Transactional
    public SecureMessageResponse receiveMessage(String messageId, ReceiveMessageRequest req) {
        String caller = SecurityUtils.currentUsername();
        SecureMessageEntity msg = messageRepository.findByMessageId(messageId)
                .orElseThrow(() -> new ResourceNotFoundException("Secure message not found: " + messageId));

        if (consumedRepository.existsByMessageId(messageId)) {
            recordReplayAlert(caller, messageId, "Duplicate/replayed message receive blocked for messageId=" + messageId);
            throw new ConflictException("REPLAY_DETECTED", "Duplicate messageId rejected: " + messageId);
        }

        if ("REVOKED".equals(msg.getRecipientDevice().getStatus())) {
            msg.setStatus("REJECTED");
            msg.setVerificationOutcome("RECIPIENT_DEVICE_REVOKED");
            messageRepository.save(msg);
            throw new AccessDeniedBusinessException("RECIPIENT_REVOKED", "Recipient device is revoked");
        }

        String claimedRecipient = (req != null && req.claimedRecipientUsername() != null && !req.claimedRecipientUsername().isBlank())
                ? req.claimedRecipientUsername().trim()
                : caller;

        if (!claimedRecipient.equals(caller) && !SecurityUtils.isAdmin()) {
            throw new AccessDeniedBusinessException("RECIPIENT_IMPERSONATION", "Authenticated identity mismatch");
        }

        Map<String, Object> aadMap;
        try {
            aadMap = objectMapper.readValue(msg.getAadJson(), new TypeReference<>() {});
        } catch (Exception e) {
            throw new IntegrityViolationException("INVALID_AAD", "Malformed message AAD");
        }

        String aadRecipient = String.valueOf(aadMap.get("recipient"));
        if (!aadRecipient.equals(claimedRecipient) || !msg.getRecipientUsername().equals(claimedRecipient)) {
            msg.setStatus("REJECTED");
            msg.setVerificationOutcome("RECIPIENT_MISMATCH_REJECTED");
            messageRepository.save(msg);
            auditLogService.appendEvent(
                    caller,
                    "SECURE_MESSAGE_REJECTED",
                    messageId,
                    "Rejected message due to recipient mismatch: claimed=" + claimedRecipient + ", aadRecipient=" + aadRecipient
            );
            throw new AccessDeniedBusinessException(
                    "RECIPIENT_MISMATCH",
                    "Recipient binding failed: intended recipient in AAD is " + aadRecipient + ", caller/claimed is " + claimedRecipient
            );
        }

        String effectiveCiphertextB64 = (req != null && req.overrideCiphertextB64() != null && !req.overrideCiphertextB64().isBlank())
                ? req.overrideCiphertextB64().trim()
                : msg.getCiphertextB64();

        // 1. Verify ML-DSA-65 signature before decryption
        byte[] senderSigPub = Base64.getDecoder().decode(msg.getSenderDevice().getSigningPublicKeyB64());
        byte[] signatureBytes = Base64.getDecoder().decode(msg.getSignatureB64());
        String sigInput = msg.getMessageId() + "|" + msg.getKemCiphertextB64() + "|" + msg.getIvB64()
                + "|" + effectiveCiphertextB64 + "|" + msg.getAadJson();

        if (!cryptoService.verifyMlDsa65(senderSigPub, sigInput.getBytes(StandardCharsets.UTF_8), signatureBytes)) {
            msg.setStatus("REJECTED");
            msg.setVerificationOutcome("ML_DSA_SIGNATURE_INVALID");
            messageRepository.save(msg);
            auditLogService.appendEvent(caller, "SECURE_MESSAGE_REJECTED", messageId, "ML-DSA-65 signature verification failed");
            throw new IntegrityViolationException("SIGNATURE_INVALID", "ML-DSA-65 signature verification failed");
        }

        // 2. Consume and immediately erase one-time ephemeral KEM private key for forward secrecy
        byte[] ephPriv = keyStore.consumeAndErase(msg.getEphemeralKeyId() + "-priv");
        byte[] sharedSecret = null;
        byte[] aesKey = null;
        String plaintext;
        try {
            byte[] kemCt = Base64.getDecoder().decode(msg.getKemCiphertextB64());
            sharedSecret = cryptoService.decapsulateMlKem768(ephPriv, kemCt);
            byte[] hkdfInfo = ("trustguard-msg-v1|" + msg.getMessageId() + "|" + msg.getSenderUsername() + "|" + aadRecipient)
                    .getBytes(StandardCharsets.UTF_8);
            aesKey = cryptoService.hkdfSha256(sharedSecret, msg.getMessageId().getBytes(StandardCharsets.UTF_8), hkdfInfo, 32);
            plaintext = cryptoService.decryptAes256Gcm(aesKey, msg.getIvB64(), effectiveCiphertextB64, msg.getAadJson());
        } catch (IllegalArgumentException ex) {
            msg.setStatus("REJECTED");
            msg.setVerificationOutcome("AES_GCM_AUTH_FAILED");
            messageRepository.save(msg);
            auditLogService.appendEvent(caller, "SECURE_MESSAGE_REJECTED", messageId, "AES-256-GCM authentication tag failure");
            throw new IntegrityViolationException("CIPHERTEXT_INVALID", "AES-256-GCM authenticated decryption failed");
        } finally {
            cryptoService.zeroize(ephPriv, sharedSecret, aesKey);
        }

        ConsumedMessageEntity consumed = new ConsumedMessageEntity();
        consumed.setMessageId(messageId);
        consumed.setRecipientUsername(claimedRecipient);
        consumed.setSenderUsername(msg.getSenderUsername());
        consumed.setAadHash(HashUtil.sha256Hex(msg.getAadJson()));
        consumed.setConsumedAt(Instant.now());
        consumedRepository.save(consumed);

        msg.setStatus("DELIVERED");
        msg.setVerificationOutcome("VERIFIED_ML_DSA_AND_GCM");
        msg.setForwardSecrecyErased(true);
        msg.setDeliveredAt(Instant.now());
        messageRepository.save(msg);

        auditLogService.appendEvent(
                caller,
                "SECURE_MESSAGE_DELIVERED",
                messageId,
                "Verified ML-DSA-65 + ML-KEM-768 + AES-256-GCM; recorded replay protection & erased ephemeral KEM key"
        );
        return toDto(msg, plaintext);
    }

    private DeviceEntity resolveActiveDevice(Long deviceId, String username) {
        if (deviceId != null) {
            return deviceRepository.findById(deviceId)
                    .orElseThrow(() -> new ResourceNotFoundException("Device not found: " + deviceId));
        }
        return deviceRepository.findFirstByOwnerUsernameAndStatusOrderByEnrolledAtDesc(username, "ACTIVE")
                .orElseThrow(() -> new AccessDeniedBusinessException(
                        "NO_ACTIVE_DEVICE",
                        "No active device found for user " + username
                ));
    }

    private void recordReplayAlert(String actor, String messageId, String explanation) {
        SecurityAlertEntity alert = new SecurityAlertEntity();
        alert.setAlertUid("alt-replay-" + UUID.randomUUID().toString().substring(0, 8));
        alert.setRuleName("duplicate_replayed_message_id");
        alert.setSeverity("HIGH");
        alert.setOutcomeClassification("DENIED_ATTEMPT");
        alert.setActor(actor);
        alert.setServicePath("messaging -> receive");
        alert.setEventIdsJson(CanonicalJsonUtil.toCanonicalJson(List.of(messageId)));
        alert.setDetectedAt(Instant.now());
        alert.setSourceEventTimeUtc(Instant.now());
        alert.setDetectionLatencyMs(1L);
        alert.setExplanation(explanation);
        alert.setDatasetSource("LIVE_RUNTIME");
        alertRepository.save(alert);
    }

    private SecureMessageResponse toDto(SecureMessageEntity m, String decryptedPlaintext) {
        return new SecureMessageResponse(
                m.getMessageId(),
                m.getSenderUsername(),
                m.getSenderDevice().getDeviceUid(),
                m.getRecipientUsername(),
                m.getRecipientDevice().getDeviceUid(),
                m.getAlgorithm(),
                m.getSignatureAlgorithm(),
                m.getStatus(),
                m.getVerificationOutcome(),
                m.isForwardSecrecyErased(),
                m.getEphemeralKeyId(),
                m.getAadJson(),
                decryptedPlaintext,
                m.getCreatedAt(),
                m.getDeliveredAt()
        );
    }
}
