package com.trustguard.controller;

import com.trustguard.dto.ReceiveMessageRequest;
import com.trustguard.dto.SecureMessageResponse;
import com.trustguard.dto.SendMessageRequest;
import com.trustguard.messaging.SecureMessagingService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/messages")
public class MessagingController {

    private final SecureMessagingService messagingService;

    public MessagingController(SecureMessagingService messagingService) {
        this.messagingService = messagingService;
    }

    @GetMapping
    public List<SecureMessageResponse> listMessages() {
        return messagingService.listMessages();
    }

    @PostMapping
    public SecureMessageResponse sendMessage(@Valid @RequestBody SendMessageRequest request) {
        return messagingService.sendMessage(request);
    }

    @PostMapping("/{id}/receive")
    public SecureMessageResponse receiveMessage(
            @PathVariable String id,
            @RequestBody(required = false) ReceiveMessageRequest request
    ) {
        return messagingService.receiveMessage(id, request);
    }
}
