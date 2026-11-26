package com.trustguard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record DeviceEnrolRequest(
        @Size(max = 64)
        String ownerUsername,
        @NotBlank(message = "deviceName is required")
        @Size(max = 120)
        String deviceName,
        Long replacesDeviceId
) {
}
