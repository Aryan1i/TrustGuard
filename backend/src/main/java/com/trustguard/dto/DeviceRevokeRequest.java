package com.trustguard.dto;

import jakarta.validation.constraints.Size;

public record DeviceRevokeRequest(
        @Size(max = 255)
        String reason
) {
}
