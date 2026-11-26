package com.trustguard.controller;

import com.trustguard.audit.AuditLogService;
import com.trustguard.dto.AuditVerifyResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/audit")
public class AuditController {

    private final AuditLogService auditLogService;

    public AuditController(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @GetMapping
    public AuditVerifyResponse.AuditListResponse listAudit() {
        return auditLogService.listAuditLogs();
    }

    @PostMapping("/verify")
    @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
    public AuditVerifyResponse verifyChain() {
        return auditLogService.verifyChain();
    }

    @PostMapping("/simulate-tamper")
    @PreAuthorize("hasRole('ADMIN')")
    public AuditVerifyResponse simulateTamper(@RequestBody(required = false) Map<String, Long> body) {
        Long seqNumber = body != null ? body.get("seqNumber") : null;
        return auditLogService.simulateTamperForDemo(seqNumber);
    }

    @PostMapping("/revert-tamper")
    @PreAuthorize("hasRole('ADMIN')")
    public AuditVerifyResponse revertTamper() {
        return auditLogService.revertSimulatedTamperForDemo();
    }
}
