package com.trustguard.dto;

import jakarta.validation.constraints.Size;

public record ReceiveMessageRequest(
        @Size(max = 64)
        String claimedRecipientUsername,
        @Size(max = 4096)
        String overrideCiphertextB64
) {
}
