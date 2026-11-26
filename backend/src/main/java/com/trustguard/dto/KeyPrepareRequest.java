package com.trustguard.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

public record KeyPrepareRequest(
        @Size(max = 80)
        String keyAlias,
        @Min(0)
        @Max(3600)
        Integer gracePeriodSeconds
) {
}
