package com.trustguard.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.crypto.ProtectedKeyStore;
import com.trustguard.util.HashUtil;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

@Service
public class JwtService {

    private static final int MIN_HMAC_SECRET_BYTES = 32;
    private static final Base64.Encoder B64_URL_ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_URL_DEC = Base64.getUrlDecoder();

    private final ProtectedKeyStore keyStore;
    private final String configuredSecret;
    private final long expirationSeconds;
    private final Environment environment;
    private final ObjectMapper mapper = new ObjectMapper();
    private byte[] hmacKey;

    public JwtService(
            ProtectedKeyStore keyStore,
            Environment environment,
            @Value("${trustguard.jwt.secret:}") String configuredSecret,
            @Value("${trustguard.jwt.expiration-seconds:28800}") long expirationSeconds
    ) {
        this.keyStore = keyStore;
        this.environment = environment;
        this.configuredSecret = configuredSecret;
        this.expirationSeconds = expirationSeconds;
    }

    @PostConstruct
    public void init() {
        if (!isDevOrTestProfile()) {
            if (configuredSecret == null || configuredSecret.isBlank()
                    || configuredSecret.getBytes(StandardCharsets.UTF_8).length < MIN_HMAC_SECRET_BYTES) {
                throw new IllegalStateException(
                        "TRUSTGUARD_JWT_SECRET (trustguard.jwt.secret) must be configured with at least "
                                + MIN_HMAC_SECRET_BYTES + " bytes outside local/test profiles"
                );
            }
        }
        this.hmacKey = keyStore.getOrCreateJwtSigningSecret(configuredSecret);
    }

    private boolean isDevOrTestProfile() {
        if (environment == null) {
            return false;
        }
        return Arrays.stream(environment.getActiveProfiles())
                .anyMatch(p -> "local".equalsIgnoreCase(p) || "test".equalsIgnoreCase(p));
    }

    public record TokenResult(String token, Instant expiresAt) {
    }

    public record VerifiedClaims(String username, String role, long tokenVersion, Instant expiresAt) {
    }

    public TokenResult generateToken(String username, String role) {
        return generateToken(username, role, 0L);
    }

    public TokenResult generateToken(String username, String role, long tokenVersion) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(expirationSeconds);
        try {
            String headerJson = mapper.writeValueAsString(Map.of("alg", "HS256", "typ", "JWT"));
            String payloadJson = mapper.writeValueAsString(Map.of(
                    "sub", username,
                    "role", role,
                    "tv", tokenVersion,
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

    public int getSigningKeyBits() {
        return hmacKey != null ? hmacKey.length * 8 : 0;
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
            // Enforce strict symmetric HS256 header: reject classical RSA/ECDSA (RS256/ES256/EdDSA) & alg=none downgrade tokens
            String headerJson = new String(B64_URL_DEC.decode(parts[0]), StandardCharsets.UTF_8);
            Map<String, Object> header = mapper.readValue(headerJson, new TypeReference<>() {});
            Object algObj = header.get("alg");
            Object typObj = header.get("typ");
            if (!(algObj instanceof String alg) || !"HS256".equals(alg)) {
                return Optional.empty();
            }
            if (!(typObj instanceof String typ) || !"JWT".equalsIgnoreCase(typ)) {
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
            Object expObj = claims.get("exp");
            Object iatObj = claims.get("iat");
            Object subObj = claims.get("sub");
            Object tvObj = claims.get("tv");
            if (!(expObj instanceof Number expNum)
                    || !(iatObj instanceof Number iatNum)
                    || !(subObj instanceof String sub)
                    || sub.isBlank()
                    || !(tvObj instanceof Number tvNum)) {
                return Optional.empty();
            }
            Instant now = Instant.now();
            Instant iat = Instant.ofEpochSecond(iatNum.longValue());
            Instant exp = Instant.ofEpochSecond(expNum.longValue());
            if (iat.isAfter(now.plusSeconds(60)) || now.isAfter(exp)) {
                return Optional.empty();
            }
            String role = claims.get("role") != null ? String.valueOf(claims.get("role")) : "";
            return Optional.of(new VerifiedClaims(sub, role, tvNum.longValue(), exp));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
