package com.trustguard.exception;

import org.springframework.http.HttpStatus;

public class RateLimitExceededException extends TrustGuardException {
    public RateLimitExceededException(String code, String message) {
        super(HttpStatus.TOO_MANY_REQUESTS, code, message);
    }
}
