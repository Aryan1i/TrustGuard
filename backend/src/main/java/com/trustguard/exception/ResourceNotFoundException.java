package com.trustguard.exception;

import org.springframework.http.HttpStatus;

public class ResourceNotFoundException extends TrustGuardException {
    public ResourceNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, "NOT_FOUND", message);
    }
}
