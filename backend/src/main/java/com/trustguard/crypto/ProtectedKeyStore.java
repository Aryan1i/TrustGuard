package com.trustguard.crypto;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustguard.exception.ResourceNotFoundException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Isolated protected key store keeping private key material and symmetric wrapping keys
 * outside ordinary database columns. Database rows store only opaque key references.
 * Supports AES-256-GCM at-rest entry encryption via TRUSTGUARD_KEYSTORE_MASTER_KEY
 * (required outside local/test profiles).
 */
@Component
public class ProtectedKeyStore {

    private static final String PREFIX = "keystore://";
    private static final String GCM_PREFIX = "gcm-v1:";
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int MIN_MASTER_KEY_BYTES = 32;

    private final Path keystorePath;
    private final Environment environment;
    private final String configuredMasterKey;
    private final ObjectMapper mapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, String> entries = new ConcurrentHashMap<>();
    private byte[] masterKey32;

    public ProtectedKeyStore(String path) {
        this(path, null, "");
    }

    @Autowired
    public ProtectedKeyStore(
            @Value("${trustguard.keystore.path:./data/trustguard-keystore.json}") String path,
            Environment environment,
            @Value("${trustguard.keystore.master-key:${TRUSTGUARD_KEYSTORE_MASTER_KEY:}}") String configuredMasterKey
    ) {
        this.keystorePath = Path.of(path).toAbsolutePath().normalize();
        this.environment = environment;
        this.configuredMasterKey = configuredMasterKey;
    }

    @PostConstruct
    public synchronized void init() {
        boolean devOrTest = isDevOrTestProfile();
        this.masterKey32 = deriveMasterKey(configuredMasterKey, !devOrTest);

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

    public synchronized boolean isMasterKeyEncryptionActive() {
        return masterKey32 != null;
    }

    public synchronized String storeSecret(String keyId, byte[] rawBytes) {
        entries.put(keyId, encodeEntry(keyId, rawBytes));
        persist();
        return PREFIX + keyId;
    }

    public synchronized byte[] loadSecret(String keyReference) {
        String keyId = stripPrefix(keyReference);
        String encoded = entries.get(keyId);
        if (encoded == null) {
            throw new ResourceNotFoundException("Key material not found in protected keystore for reference");
        }
        return decodeEntry(keyId, encoded);
    }

    public synchronized byte[] consumeAndErase(String keyReference) {
        String keyId = stripPrefix(keyReference);
        String encoded = entries.remove(keyId);
        if (encoded == null) {
            throw new ResourceNotFoundException("Ephemeral key already erased or missing");
        }
        persist();
        return decodeEntry(keyId, encoded);
    }

    public synchronized boolean contains(String keyReference) {
        return entries.containsKey(stripPrefix(keyReference));
    }

    public synchronized byte[] getOrCreateJwtSigningSecret(String configuredSecret) {
        if (configuredSecret != null && !configuredSecret.isBlank()) {
            byte[] raw = configuredSecret.getBytes(StandardCharsets.UTF_8);
            if (raw.length >= 32) {
                return raw;
            }
        }
        String keyId = "jwt-hmac-signing-key";
        if (!entries.containsKey(keyId)) {
            byte[] randomKey = new byte[48];
            secureRandom.nextBytes(randomKey);
            try {
                entries.put(keyId, encodeEntry(keyId, randomKey));
                persist();
            } finally {
                Arrays.fill(randomKey, (byte) 0);
            }
        }
        return decodeEntry(keyId, entries.get(keyId));
    }

    public synchronized byte[] getOrCreateBackupHmacKey() {
        String keyId = "backup-integrity-hmac-key";
        if (!entries.containsKey(keyId)) {
            byte[] randomKey = new byte[32];
            secureRandom.nextBytes(randomKey);
            try {
                entries.put(keyId, encodeEntry(keyId, randomKey));
                persist();
            } finally {
                Arrays.fill(randomKey, (byte) 0);
            }
        }
        return decodeEntry(keyId, entries.get(keyId));
    }

    public synchronized void clearForTest() {
        entries.clear();
        persist();
    }

    private boolean isDevOrTestProfile() {
        if (environment == null) {
            return true;
        }
        return Arrays.stream(environment.getActiveProfiles())
                .anyMatch(p -> "local".equalsIgnoreCase(p) || "test".equalsIgnoreCase(p));
    }

    private byte[] deriveMasterKey(String secret, boolean required) {
        if (secret == null || secret.isBlank()) {
            if (required) {
                throw new IllegalStateException(
                        "TRUSTGUARD_KEYSTORE_MASTER_KEY (trustguard.keystore.master-key) must be configured "
                                + "with at least 32 bytes outside local/test profiles"
                );
            }
            return null;
        }
        String trimmed = secret.trim();
        byte[] utf8 = trimmed.getBytes(StandardCharsets.UTF_8);
        byte[] material = null;
        try {
            byte[] decoded = Base64.getDecoder().decode(trimmed);
            if (decoded.length >= MIN_MASTER_KEY_BYTES) {
                material = decoded;
            }
        } catch (IllegalArgumentException ignored) {
            // Treat as UTF-8 passphrase when not Base64
        }
        if (material == null) {
            if (utf8.length < MIN_MASTER_KEY_BYTES) {
                throw new IllegalStateException(
                        "TRUSTGUARD_KEYSTORE_MASTER_KEY must provide at least " + MIN_MASTER_KEY_BYTES + " bytes"
                );
            }
            material = utf8;
        }
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update("trustguard-keystore-kek-v1|".getBytes(StandardCharsets.UTF_8));
            return sha256.digest(material);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to derive keystore master encryption key", e);
        }
    }

    private String encodeEntry(String keyId, byte[] rawBytes) {
        if (masterKey32 == null) {
            return Base64.getEncoder().encodeToString(rawBytes);
        }
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(masterKey32, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(("tg-ks-v1|" + keyId).getBytes(StandardCharsets.UTF_8));
            byte[] ct = cipher.doFinal(rawBytes);
            return GCM_PREFIX + Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt keystore entry", e);
        }
    }

    private byte[] decodeEntry(String keyId, String stored) {
        if (stored.startsWith(GCM_PREFIX)) {
            if (masterKey32 == null) {
                throw new IllegalStateException("Encrypted keystore entry encountered without TRUSTGUARD_KEYSTORE_MASTER_KEY");
            }
            String[] parts = stored.substring(GCM_PREFIX.length()).split(":", 2);
            if (parts.length != 2) {
                throw new IllegalStateException("Corrupt encrypted keystore entry format");
            }
            try {
                byte[] iv = Base64.getDecoder().decode(parts[0]);
                byte[] ct = Base64.getDecoder().decode(parts[1]);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(masterKey32, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
                cipher.updateAAD(("tg-ks-v1|" + keyId).getBytes(StandardCharsets.UTF_8));
                return cipher.doFinal(ct);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to decrypt keystore entry (invalid master key or tampered entry)", e);
            }
        }
        if (masterKey32 != null && !isDevOrTestProfile()) {
            throw new IllegalStateException("Plaintext keystore entry rejected outside local/test when master encryption is required");
        }
        return Base64.getDecoder().decode(stored);
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
