package com.trustguard.exception;

import org.springframework.http.HttpStatus;

public class ConflictException extends TrustGuardException {
    public ConflictException(String code, String message) {
        super(HttpStatus.CONFLICT, code, message);
    }
}
