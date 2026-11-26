package com.trustguard.dto;

import jakarta.validation.constraints.Size;

public record KeyAcknowledgeRequest(
        @Size(max = 64)
        String nodeCode
) {
}
