package com.trustguard.crypto;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.exception.ResourceNotFoundException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Isolated protected key store keeping private key material and symmetric wrapping keys
 * outside ordinary database columns. Database rows store only opaque key references.
 */
@Component
public class ProtectedKeyStore {

    private static final String PREFIX = "keystore://";
    private final Path keystorePath;
    private final ObjectMapper mapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, String> entries = new ConcurrentHashMap<>();

    public ProtectedKeyStore(@Value("${trustguard.keystore.path:./data/trustguard-keystore.json}") String path) {
        this.keystorePath = Path.of(path).toAbsolutePath().normalize();
    }

    @PostConstruct
    public synchronized void init() {
        try {
            if (keystorePath.getParent() != null) {
                Files.createDirectories(keystorePath.getParent());
            }
            if (Files.exists(keystorePath)) {
                Map<String, String> loaded = mapper.readValue(
                        Files.readString(keystorePath),
                        new TypeReference<>() {}
                );
                entries.clear();
                entries.putAll(loaded);
            } else {
                persist();
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize protected key store", e);
        }
    }

    public synchronized String storeSecret(String keyId, byte[] rawBytes) {
        String encoded = Base64.getEncoder().encodeToString(rawBytes);
        entries.put(keyId, encoded);
        persist();
        return PREFIX + keyId;
    }

    public synchronized byte[] loadSecret(String keyReference) {
        String keyId = stripPrefix(keyReference);
        String encoded = entries.get(keyId);
        if (encoded == null) {
            throw new ResourceNotFoundException("Key material not found in protected keystore for reference");
        }
        return Base64.getDecoder().decode(encoded);
    }

    public synchronized byte[] consumeAndErase(String keyReference) {
        String keyId = stripPrefix(keyReference);
        String encoded = entries.remove(keyId);
        if (encoded == null) {
            throw new ResourceNotFoundException("Ephemeral key already erased or missing");
        }
        persist();
        return Base64.getDecoder().decode(encoded);
    }

    public synchronized boolean contains(String keyReference) {
        return entries.containsKey(stripPrefix(keyReference));
    }

    public synchronized byte[] getOrCreateJwtSigningSecret(String configuredSecret) {
        if (configuredSecret != null && !configuredSecret.isBlank()) {
            byte[] raw = configuredSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (raw.length >= 32) {
                return raw;
            }
        }
        String keyId = "jwt-hmac-signing-key";
        if (!entries.containsKey(keyId)) {
            byte[] randomKey = new byte[48];
            secureRandom.nextBytes(randomKey);
            entries.put(keyId, Base64.getEncoder().encodeToString(randomKey));
            persist();
        }
        return Base64.getDecoder().decode(entries.get(keyId));
    }

    public synchronized byte[] getOrCreateBackupHmacKey() {
        String keyId = "backup-integrity-hmac-key";
        if (!entries.containsKey(keyId)) {
            byte[] randomKey = new byte[32];
            secureRandom.nextBytes(randomKey);
            entries.put(keyId, Base64.getEncoder().encodeToString(randomKey));
            persist();
        }
        return Base64.getDecoder().decode(entries.get(keyId));
    }

    public synchronized void clearForTest() {
        entries.clear();
        persist();
    }

    private String stripPrefix(String keyReference) {
        if (keyReference != null && keyReference.startsWith(PREFIX)) {
            return keyReference.substring(PREFIX.length());
        }
        return keyReference;
    }

    private void persist() {
        try {
            if (keystorePath.getParent() != null) {
                Files.createDirectories(keystorePath.getParent());
            }
            Path temp = Files.createTempFile(keystorePath.getParent(), ".tg-ks-", ".tmp");
            mapper.writerWithDefaultPrettyPrinter().writeValue(temp.toFile(), entries);
            try {
                Set<PosixFilePermission> ownerOnly = EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE
                );
                Files.setPosixFilePermissions(temp, ownerOnly);
            } catch (UnsupportedOperationException ignored) {
                // Non-POSIX filesystems
            }
            Files.move(temp, keystorePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to persist protected key store", e);
        }
    }
}
