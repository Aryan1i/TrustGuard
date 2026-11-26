package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "consumed_messages")
public class ConsumedMessageEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "message_id", nullable = false, unique = true, length = 96)
    private String messageId;

    @Column(name = "recipient_username", nullable = false, length = 64)
    private String recipientUsername;

    @Column(name = "sender_username", nullable = false, length = 64)
    private String senderUsername;

    @Column(name = "aad_hash", nullable = false, length = 64)
    private String aadHash;

    @Column(name = "consumed_at", nullable = false)
    private Instant consumedAt = Instant.now();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getMessageId() { return messageId; }
    public void setMessageId(String messageId) { this.messageId = messageId; }
    public String getRecipientUsername() { return recipientUsername; }
    public void setRecipientUsername(String recipientUsername) { this.recipientUsername = recipientUsername; }
    public String getSenderUsername() { return senderUsername; }
    public void setSenderUsername(String senderUsername) { this.senderUsername = senderUsername; }
    public String getAadHash() { return aadHash; }
    public void setAadHash(String aadHash) { this.aadHash = aadHash; }
    public Instant getConsumedAt() { return consumedAt; }
    public void setConsumedAt(Instant consumedAt) { this.consumedAt = consumedAt; }
}
