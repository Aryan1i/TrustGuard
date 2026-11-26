package com.trustguard.controller;

import com.trustguard.dto.KeyAcknowledgeRequest;
import com.trustguard.dto.KeyPrepareRequest;
import com.trustguard.dto.KeyVersionResponse;
import com.trustguard.service.KeyManagementService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/keys")
@org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
public class KeyManagementController {

    private final KeyManagementService keyManagementService;

    public KeyManagementController(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    @GetMapping
    public List<KeyVersionResponse> listKeys() {
        return keyManagementService.listKeys();
    }

    @GetMapping("/rotation-status")
    public Map<String, Object> getRotationStatus() {
        return keyManagementService.getRotationStatus();
    }

    @PostMapping("/prepare")
    @PreAuthorize("hasRole('ADMIN')")
    public KeyVersionResponse prepareKey(@Valid @RequestBody(required = false) KeyPrepareRequest request) {
        String alias = request != null ? request.keyAlias() : null;
        Integer grace = request != null ? request.gracePeriodSeconds() : null;
        return keyManagementService.prepareKey(alias, grace);
    }

    @PostMapping("/{id}/acknowledge")
    @PreAuthorize("hasRole('ADMIN')")
    public KeyVersionResponse acknowledgeKey(
            @PathVariable Long id,
            @Valid @RequestBody(required = false) KeyAcknowledgeRequest request
    ) {
        return keyManagementService.acknowledgeKey(id, request != null ? request.nodeCode() : null);
    }

    @PostMapping("/{id}/commit")
    @PreAuthorize("hasRole('ADMIN')")
    public KeyVersionResponse commitKey(@PathVariable Long id) {
        return keyManagementService.commitKey(id);
    }
}
