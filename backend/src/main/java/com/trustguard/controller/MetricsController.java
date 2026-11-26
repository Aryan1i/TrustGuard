package com.trustguard.controller;

import com.trustguard.dto.SecurityMetricsResponse;
import com.trustguard.metrics.SecurityMetricsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/metrics")
public class MetricsController {

    private final SecurityMetricsService metricsService;

    public MetricsController(SecurityMetricsService metricsService) {
        this.metricsService = metricsService;
    }

    @GetMapping("/security")
    public SecurityMetricsResponse getSecurityMetrics() {
        return metricsService.calculateMetrics();
    }
}
