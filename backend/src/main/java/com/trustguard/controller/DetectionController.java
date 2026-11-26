package com.trustguard.controller;

import com.trustguard.detection.DetectionOrchestrationService;
import com.trustguard.dto.DetectionEvaluationResponse;
import com.trustguard.dto.DetectionEvaluationResponse.AlertDto;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1")
public class DetectionController {

    private final DetectionOrchestrationService detectionService;

    public DetectionController(DetectionOrchestrationService detectionService) {
        this.detectionService = detectionService;
    }

    @GetMapping("/alerts")
    public List<AlertDto> listAlerts() {
        return detectionService.listAllAlerts();
    }

    @PostMapping("/detection/evaluate")
    public DetectionEvaluationResponse evaluatePracticeEvents() {
        return detectionService.evaluatePracticeDataset();
    }
}
