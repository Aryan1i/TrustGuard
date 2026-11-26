package com.trustguard.controller;

import com.trustguard.dto.DeviceEnrolRequest;
import com.trustguard.dto.DeviceResponse;
import com.trustguard.dto.DeviceRevokeRequest;
import com.trustguard.entity.SimulatedNodeEntity;
import com.trustguard.service.DeviceService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class DeviceController {

    private final DeviceService deviceService;

    public DeviceController(DeviceService deviceService) {
        this.deviceService = deviceService;
    }

    @GetMapping("/users")
    public List<Map<String, Object>> listUsers() {
        return deviceService.listUsers();
    }

    @GetMapping("/devices")
    public List<DeviceResponse> listDevices() {
        return deviceService.listDevices();
    }

    @PostMapping("/devices/enrol")
    public DeviceResponse enrolDevice(@Valid @RequestBody DeviceEnrolRequest request) {
        return deviceService.enrolDevice(request);
    }

    @PostMapping("/devices/{id}/revoke")
    public Map<String, Object> revokeDevice(
            @PathVariable Long id,
            @RequestBody(required = false) DeviceRevokeRequest request
    ) {
        return deviceService.revokeDevice(id, request != null ? request.reason() : null);
    }

    @GetMapping("/nodes")
    public List<SimulatedNodeEntity> listNodes() {
        return deviceService.listNodes();
    }

    @PostMapping("/nodes/{id}/toggle-failure")
    @PreAuthorize("hasRole('ADMIN')")
    public SimulatedNodeEntity toggleNodeAckFailure(
            @PathVariable Long id,
            @RequestBody Map<String, Boolean> body
    ) {
        boolean simulate = Boolean.TRUE.equals(body.get("simulateAckFailure"));
        return deviceService.toggleNodeAckFailure(id, simulate);
    }
}
