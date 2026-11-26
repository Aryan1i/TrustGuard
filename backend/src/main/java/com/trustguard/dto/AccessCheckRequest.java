package com.trustguard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AccessCheckRequest(
        @Size(max = 64)
        String simulatedActor,
        boolean simulationMode,
        Long deviceId,
        @NotBlank(message = "sourceService is required")
        @Size(max = 64)
        String sourceService,
        @NotBlank(message = "targetService is required")
        @Size(max = 64)
        String targetService,
        @NotBlank(message = "resourceKey is required")
        @Size(max = 80)
        String resourceKey,
        @NotBlank(message = "action is required")
        @Size(max = 40)
        String action,
        @Size(max = 64)
        String nodeCode,
        Integer requestedKeyVersion,
        boolean protectedRead,
        @Size(max = 256)
        String challenge,
        @Size(max = 4096)
        String publicKeyB64,
        @Size(max = 96)
        String requestId
) {
}
