package com.trustguard.controller;

import com.trustguard.crypto.PostQuantumPostureService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/crypto")
public class CryptoController {

    private final PostQuantumPostureService postureService;

    public CryptoController(PostQuantumPostureService postureService) {
        this.postureService = postureService;
    }

    @GetMapping("/pqc-status")
    public Map<String, Object> pqcStatus() {
        return postureService.inspectPqcStatus();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/verify-shor-resilience")
    public Map<String, Object> verifyShorResilience() {
        return postureService.verifyShorResilience();
    }
}
