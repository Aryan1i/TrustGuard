package com.trustguard.controller;

import com.trustguard.entity.SessionRecordEntity;
import com.trustguard.service.SessionService;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sessions")
public class SessionController {

    private final SessionService sessionService;

    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @GetMapping
    public List<Map<String, Object>> listSessions() {
        return sessionService.listSessions().stream().map(this::toSummary).toList();
    }

    @PostMapping("/open")
    public Map<String, Object> openSession(@RequestBody(required = false) Map<String, Long> body) {
        Long peerDeviceId = body != null ? body.get("peerDeviceId") : null;
        return toSummary(sessionService.openSession(peerDeviceId));
    }

    @PostMapping("/{sessionId}/close")
    public Map<String, Object> closeSession(@PathVariable String sessionId) {
        return toSummary(sessionService.closeSession(sessionId));
    }

    @PostMapping("/{sessionId}/resume")
    public Map<String, Object> resumeSession(@PathVariable String sessionId) {
        return toSummary(sessionService.resumeSession(sessionId));
    }

    @PostMapping("/run-tests")
    public List<Map<String, Object>> runSuite() {
        return sessionService.runRepeatableSessionAndDeliverySuite();
    }

    private Map<String, Object> toSummary(SessionRecordEntity s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("sessionId", s.getSessionId());
        m.put("actorUsername", s.getActorUsername());
        m.put("deviceUid", s.getDevice() != null ? s.getDevice().getDeviceUid() : null);
        m.put("peerDeviceUid", s.getPeerDevice() != null ? s.getPeerDevice().getDeviceUid() : null);
        m.put("status", s.getStatus());
        m.put("resumedCount", s.getResumedCount());
        m.put("createdAt", s.getCreatedAt());
        m.put("lastActiveAt", s.getLastActiveAt());
        m.put("expiresAt", s.getExpiresAt());
        return m;
    }
}
