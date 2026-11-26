package com.trustguard.exception;

import org.springframework.http.HttpStatus;

public class AccessDeniedBusinessException extends TrustGuardException {
    public AccessDeniedBusinessException(String code, String message) {
        super(HttpStatus.FORBIDDEN, code, message);
    }
}
