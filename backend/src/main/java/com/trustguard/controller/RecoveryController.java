package com.trustguard.controller;

import com.trustguard.dto.BackupResponse;
import com.trustguard.recovery.BackupRecoveryService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/backups")
@PreAuthorize("hasRole('ADMIN')")
public class RecoveryController {

    private final BackupRecoveryService backupRecoveryService;

    public RecoveryController(BackupRecoveryService backupRecoveryService) {
        this.backupRecoveryService = backupRecoveryService;
    }

    @GetMapping
    public List<BackupResponse> listBackups() {
        return backupRecoveryService.listBackups();
    }

    @PostMapping("/create")
    @PreAuthorize("hasRole('ADMIN')")
    public BackupResponse createBackup() {
        return backupRecoveryService.createBackup();
    }

    @PostMapping("/{id}/verify")
    public BackupResponse verifyBackup(@PathVariable String id) {
        return backupRecoveryService.verifyBackup(id);
    }

    @PostMapping("/{id}/restore")
    @PreAuthorize("hasRole('ADMIN')")
    public BackupResponse restoreBackup(@PathVariable String id) {
        return backupRecoveryService.restoreBackup(id);
    }

    @PostMapping("/{id}/simulate-corruption")
    @PreAuthorize("hasRole('ADMIN')")
    public BackupResponse simulateCorruption(@PathVariable String id) {
        return backupRecoveryService.simulateCorruption(id);
    }
}
