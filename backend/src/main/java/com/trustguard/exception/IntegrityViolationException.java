package com.trustguard.exception;

import org.springframework.http.HttpStatus;

public class IntegrityViolationException extends TrustGuardException {
    public IntegrityViolationException(String code, String message) {
        super(HttpStatus.UNPROCESSABLE_ENTITY, code, message);
    }
}
