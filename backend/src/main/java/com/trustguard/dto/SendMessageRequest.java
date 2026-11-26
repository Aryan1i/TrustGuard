package com.trustguard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SendMessageRequest(
        @NotBlank(message = "recipientUsername is required")
        @Size(max = 64)
        String recipientUsername,
        Long senderDeviceId,
        Long recipientDeviceId,
        @NotBlank(message = "plaintext is required")
        @Size(max = 4096)
        String plaintext,
        @Size(max = 96)
        String customMessageId,
        boolean simulateTamperedRecipient,
        boolean simulateTamperedCiphertext
) {
}
