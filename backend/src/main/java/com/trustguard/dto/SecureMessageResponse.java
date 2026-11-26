package com.trustguard.dto;

import java.time.Instant;

public record SecureMessageResponse(
        String messageId,
        String senderUsername,
        String senderDeviceUid,
        String recipientUsername,
        String recipientDeviceUid,
        String algorithm,
        String signatureAlgorithm,
        String status,
        String verificationOutcome,
        boolean forwardSecrecyErased,
        String ephemeralKeyId,
        String aadJson,
        String decryptedPlaintext,
        Instant createdAt,
        Instant deliveredAt
) {
}
