package com.trustguard.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.crypto.ProtectedKeyStore;
import com.trustguard.util.HashUtil;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

@Service
public class JwtService {

    private static final Base64.Encoder B64_URL_ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_URL_DEC = Base64.getUrlDecoder();

    private final ProtectedKeyStore keyStore;
    private final String configuredSecret;
    private final long expirationSeconds;
    private final ObjectMapper mapper = new ObjectMapper();
    private byte[] hmacKey;

    public JwtService(
            ProtectedKeyStore keyStore,
            @Value("${trustguard.jwt.secret:}") String configuredSecret,
            @Value("${trustguard.jwt.expiration-seconds:28800}") long expirationSeconds
    ) {
        this.keyStore = keyStore;
        this.configuredSecret = configuredSecret;
        this.expirationSeconds = expirationSeconds;
    }

    @PostConstruct
    public void init() {
        this.hmacKey = keyStore.getOrCreateJwtSigningSecret(configuredSecret);
    }

    public record TokenResult(String token, Instant expiresAt) {
    }

    public record VerifiedClaims(String username, String role, Instant expiresAt) {
    }

    public TokenResult generateToken(String username, String role) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(expirationSeconds);
        try {
            String headerJson = mapper.writeValueAsString(Map.of("alg", "HS256", "typ", "JWT"));
            String payloadJson = mapper.writeValueAsString(Map.of(
                    "sub", username,
                    "role", role,
                    "iat", now.getEpochSecond(),
                    "exp", exp.getEpochSecond()
            ));
            String headerB64 = B64_URL_ENC.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String payloadB64 = B64_URL_ENC.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
            String signingInput = headerB64 + "." + payloadB64;
            String sigHex = HashUtil.hmacSha256Hex(hmacKey, signingInput.getBytes(StandardCharsets.UTF_8));
            String sigB64 = B64_URL_ENC.encodeToString(sigHex.getBytes(StandardCharsets.UTF_8));
            return new TokenResult(signingInput + "." + sigB64, exp);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign JWT", e);
        }
    }

    public Optional<VerifiedClaims> verifyToken(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return Optional.empty();
            }
            String signingInput = parts[0] + "." + parts[1];
            String expectedSigHex = HashUtil.hmacSha256Hex(hmacKey, signingInput.getBytes(StandardCharsets.UTF_8));
            String actualSigHex = new String(B64_URL_DEC.decode(parts[2]), StandardCharsets.UTF_8);
            if (!HashUtil.constantTimeEquals(expectedSigHex, actualSigHex)) {
                return Optional.empty();
            }
            String payloadJson = new String(B64_URL_DEC.decode(parts[1]), StandardCharsets.UTF_8);
            Map<String, Object> claims = mapper.readValue(payloadJson, new TypeReference<>() {});
            long expEpoch = ((Number) claims.get("exp")).longValue();
            Instant exp = Instant.ofEpochSecond(expEpoch);
            if (Instant.now().isAfter(exp)) {
                return Optional.empty();
            }
            String sub = String.valueOf(claims.get("sub"));
            String role = String.valueOf(claims.get("role"));
            return Optional.of(new VerifiedClaims(sub, role, exp));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
