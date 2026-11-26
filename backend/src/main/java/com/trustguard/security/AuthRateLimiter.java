package com.trustguard.security;

import com.trustguard.exception.RateLimitExceededException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory sliding-window authentication rate limiter enforcing per-username
 * and per-client-IP failure thresholds with temporary lockout.
 */
@Component
public class AuthRateLimiter {

    private static final int MAX_BUCKET_ENTRIES = 10_000;

    private final int maxFailuresPerUsername;
    private final int maxFailuresPerIp;
    private final long windowSeconds;
    private final long lockoutSeconds;

    private final ConcurrentHashMap<String, AttemptWindow> usernameBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AttemptWindow> ipBuckets = new ConcurrentHashMap<>();

    public AuthRateLimiter(
            @Value("${trustguard.auth.rate-limit.max-failures-per-username:5}") int maxFailuresPerUsername,
            @Value("${trustguard.auth.rate-limit.max-failures-per-ip:25}") int maxFailuresPerIp,
            @Value("${trustguard.auth.rate-limit.window-seconds:300}") long windowSeconds,
            @Value("${trustguard.auth.rate-limit.lockout-seconds:300}") long lockoutSeconds
    ) {
        this.maxFailuresPerUsername = Math.max(1, maxFailuresPerUsername);
        this.maxFailuresPerIp = Math.max(1, maxFailuresPerIp);
        this.windowSeconds = Math.max(1, windowSeconds);
        this.lockoutSeconds = Math.max(1, lockoutSeconds);
    }

    public void checkAllowed(String username, String clientIp) {
        Instant now = Instant.now();
        String userKey = normalizeUsername(username);
        if (userKey != null && isLocked(usernameBuckets, userKey, now)) {
            throw new RateLimitExceededException(
                    "AUTH_RATE_LIMITED",
                    "Too many failed authentication attempts for this username. Please wait before retrying."
            );
        }
        String ipKey = normalizeIp(clientIp);
        if (isLocked(ipBuckets, ipKey, now)) {
            throw new RateLimitExceededException(
                    "AUTH_RATE_LIMITED",
                    "Too many failed authentication attempts from this IP address. Please wait before retrying."
            );
        }
    }

    public void recordFailure(String username, String clientIp) {
        Instant now = Instant.now();
        String userKey = normalizeUsername(username);
        if (userKey != null) {
            evictIfOversized(usernameBuckets, now);
            incrementAndMaybeLock(usernameBuckets, userKey, now, maxFailuresPerUsername);
        }
        String ipKey = normalizeIp(clientIp);
        evictIfOversized(ipBuckets, now);
        incrementAndMaybeLock(ipBuckets, ipKey, now, maxFailuresPerIp);
    }

    public void recordSuccess(String username) {
        String userKey = normalizeUsername(username);
        if (userKey != null) {
            usernameBuckets.remove(userKey);
        }
    }

    public void clearAll() {
        usernameBuckets.clear();
        ipBuckets.clear();
    }

    private boolean isLocked(ConcurrentHashMap<String, AttemptWindow> buckets, String key, Instant now) {
        AttemptWindow window = buckets.get(key);
        if (window == null) {
            return false;
        }
        synchronized (window) {
            if (window.lockedUntil != null && now.isBefore(window.lockedUntil)) {
                return true;
            }
            if (window.lockedUntil != null && !now.isBefore(window.lockedUntil)) {
                window.lockedUntil = null;
                window.failures.clear();
            }
            return false;
        }
    }

    private void incrementAndMaybeLock(
            ConcurrentHashMap<String, AttemptWindow> buckets,
            String key,
            Instant now,
            int threshold
    ) {
        AttemptWindow window = buckets.computeIfAbsent(key, ignored -> new AttemptWindow());
        Instant cutoff = now.minusSeconds(windowSeconds);
        synchronized (window) {
            while (!window.failures.isEmpty() && window.failures.peekFirst().isBefore(cutoff)) {
                window.failures.pollFirst();
            }
            window.failures.addLast(now);
            if (window.failures.size() >= threshold) {
                window.lockedUntil = now.plusSeconds(lockoutSeconds);
            }
        }
    }

    private void evictIfOversized(ConcurrentHashMap<String, AttemptWindow> buckets, Instant now) {
        if (buckets.size() < MAX_BUCKET_ENTRIES) {
            return;
        }
        Instant cutoff = now.minusSeconds(windowSeconds);
        buckets.entrySet().removeIf(entry -> {
            AttemptWindow w = entry.getValue();
            synchronized (w) {
                if (w.lockedUntil != null && now.isBefore(w.lockedUntil)) {
                    return false;
                }
                while (!w.failures.isEmpty() && w.failures.peekFirst().isBefore(cutoff)) {
                    w.failures.pollFirst();
                }
                return w.failures.isEmpty();
            }
        });
    }

    private String normalizeUsername(String username) {
        if (username == null || username.isBlank()) {
            return null;
        }
        return username.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeIp(String clientIp) {
        if (clientIp == null || clientIp.isBlank()) {
            return "unknown";
        }
        return clientIp.trim();
    }

    private static final class AttemptWindow {
        private final Deque<Instant> failures = new ArrayDeque<>();
        private Instant lockedUntil;
    }
}
