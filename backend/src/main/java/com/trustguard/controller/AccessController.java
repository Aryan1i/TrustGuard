package com.trustguard.controller;

import com.trustguard.dto.AccessCheckRequest;
import com.trustguard.dto.AccessCheckResponse;
import com.trustguard.service.AccessControlService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class AccessController {

    private final AccessControlService accessControlService;

    public AccessController(AccessControlService accessControlService) {
        this.accessControlService = accessControlService;
    }

    @GetMapping("/resources")
    public List<Map<String, Object>> listResources() {
        return accessControlService.listResources();
    }

    @PostMapping("/access/check")
    public AccessCheckResponse checkAccess(@Valid @RequestBody AccessCheckRequest request) {
        return accessControlService.checkAccess(request);
    }

    @GetMapping("/access/events")
    public List<Map<String, Object>> listAccessEvents() {
        return accessControlService.listAccessEvents();
    }
}
