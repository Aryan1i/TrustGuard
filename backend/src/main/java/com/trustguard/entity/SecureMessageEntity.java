package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "secure_messages")
public class SecureMessageEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "message_id", nullable = false, unique = true, length = 96)
    private String messageId;

    @Column(name = "sender_username", nullable = false, length = 64)
    private String senderUsername;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "sender_device_id", nullable = false)
    private DeviceEntity senderDevice;

    @Column(name = "recipient_username", nullable = false, length = 64)
    private String recipientUsername;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "recipient_device_id", nullable = false)
    private DeviceEntity recipientDevice;

    @Column(nullable = false, length = 80)
    private String algorithm;

    @Column(name = "signature_algorithm", nullable = false, length = 40)
    private String signatureAlgorithm;

    @Column(name = "kem_ciphertext_b64", nullable = false, columnDefinition = "TEXT")
    private String kemCiphertextB64;

    @Column(name = "iv_b64", nullable = false, length = 64)
    private String ivB64;

    @Column(name = "ciphertext_b64", nullable = false, columnDefinition = "TEXT")
    private String ciphertextB64;

    @Column(name = "aad_json", nullable = false, columnDefinition = "TEXT")
    private String aadJson;

    @Column(name = "signature_b64", nullable = false, columnDefinition = "TEXT")
    private String signatureB64;

    @Column(name = "ephemeral_key_id", nullable = false, length = 96)
    private String ephemeralKeyId;

    @Column(name = "forward_secrecy_erased", nullable = false)
    private boolean forwardSecrecyErased = true;

    @Column(nullable = false, length = 32)
    private String status;

    @Column(name = "verification_outcome", nullable = false, length = 80)
    private String verificationOutcome;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "delivered_at")
    private Instant deliveredAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getMessageId() { return messageId; }
    public void setMessageId(String messageId) { this.messageId = messageId; }
    public String getSenderUsername() { return senderUsername; }
    public void setSenderUsername(String senderUsername) { this.senderUsername = senderUsername; }
    public DeviceEntity getSenderDevice() { return senderDevice; }
    public void setSenderDevice(DeviceEntity senderDevice) { this.senderDevice = senderDevice; }
    public String getRecipientUsername() { return recipientUsername; }
    public void setRecipientUsername(String recipientUsername) { this.recipientUsername = recipientUsername; }
    public DeviceEntity getRecipientDevice() { return recipientDevice; }
    public void setRecipientDevice(DeviceEntity recipientDevice) { this.recipientDevice = recipientDevice; }
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }
    public String getKemCiphertextB64() { return kemCiphertextB64; }
    public void setKemCiphertextB64(String kemCiphertextB64) { this.kemCiphertextB64 = kemCiphertextB64; }
    public String getIvB64() { return ivB64; }
    public void setIvB64(String ivB64) { this.ivB64 = ivB64; }
    public String getCiphertextB64() { return ciphertextB64; }
    public void setCiphertextB64(String ciphertextB64) { this.ciphertextB64 = ciphertextB64; }
    public String getAadJson() { return aadJson; }
    public void setAadJson(String aadJson) { this.aadJson = aadJson; }
    public String getSignatureB64() { return signatureB64; }
    public void setSignatureB64(String signatureB64) { this.signatureB64 = signatureB64; }
    public String getEphemeralKeyId() { return ephemeralKeyId; }
    public void setEphemeralKeyId(String ephemeralKeyId) { this.ephemeralKeyId = ephemeralKeyId; }
    public boolean isForwardSecrecyErased() { return forwardSecrecyErased; }
    public void setForwardSecrecyErased(boolean forwardSecrecyErased) { this.forwardSecrecyErased = forwardSecrecyErased; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getVerificationOutcome() { return verificationOutcome; }
    public void setVerificationOutcome(String verificationOutcome) { this.verificationOutcome = verificationOutcome; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getDeliveredAt() { return deliveredAt; }
    public void setDeliveredAt(Instant deliveredAt) { this.deliveredAt = deliveredAt; }
}
