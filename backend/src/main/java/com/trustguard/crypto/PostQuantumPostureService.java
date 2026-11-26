package com.trustguard.crypto;

import com.trustguard.audit.AuditLogService;
import com.trustguard.entity.DeviceEntity;
import com.trustguard.entity.KeyVersionEntity;
import com.trustguard.repository.DeviceRepository;
import com.trustguard.repository.KeyVersionRepository;
import com.trustguard.security.JwtService;
import com.trustguard.security.SecurityUtils;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Evaluates and verifies TrustGuard's cryptographic resistance against Shor's
 * quantum factoring/discrete-logarithm algorithm and classical-key downgrade attacks.
 */
@Service
public class PostQuantumPostureService {

    private static final List<String> CLASSICAL_ASYMMETRIC_MARKERS =
            List.of("RSA", "ECDSA", "ECDH", "ED25519", "EDDSA", "DSA", "DIFFIE");

    private final KeyVersionRepository keyVersionRepository;
    private final DeviceRepository deviceRepository;
    private final PostQuantumCryptoService cryptoService;
    private final JwtService jwtService;
    private final AuditLogService auditLogService;

    public PostQuantumPostureService(
            KeyVersionRepository keyVersionRepository,
            DeviceRepository deviceRepository,
            PostQuantumCryptoService cryptoService,
            JwtService jwtService,
            AuditLogService auditLogService
    ) {
        this.keyVersionRepository = keyVersionRepository;
        this.deviceRepository = deviceRepository;
        this.cryptoService = cryptoService;
        this.jwtService = jwtService;
        this.auditLogService = auditLogService;
    }

    public Map<String, Object> inspectPqcStatus() {
        List<KeyVersionEntity> keys = keyVersionRepository.findAll();
        List<DeviceEntity> devices = deviceRepository.findAll();

        int verifiedKeys = 0;
        int classicalKeys = 0;
        for (KeyVersionEntity k : keys) {
            String alg = String.valueOf(k.getAlgorithm()).toUpperCase(Locale.ROOT);
            boolean hasClassical = containsClassicalMarker(alg) && !alg.contains("ML-DSA") && !alg.contains("ML-KEM");
            if (hasClassical) {
                classicalKeys++;
            }
            if (alg.contains("ML-KEM-768") && validateBase64KemKey(k.getPublicKeyB64())) {
                verifiedKeys++;
            }
        }

        int activeDevices = 0;
        int verifiedDevices = 0;
        int classicalDevices = 0;
        for (DeviceEntity d : devices) {
            if (!"ACTIVE".equals(d.getStatus())) {
                continue;
            }
            activeDevices++;
            String alg = String.valueOf(d.getKeyAlgorithm()).toUpperCase(Locale.ROOT);
            boolean hasClassical = containsClassicalMarker(alg) && !alg.contains("ML-DSA") && !alg.contains("ML-KEM");
            if (hasClassical) {
                classicalDevices++;
            }
            if (alg.contains("ML-KEM-768")
                    && alg.contains("ML-DSA-65")
                    && validateBase64KemKey(d.getPublicKeyB64())
                    && validateBase64DsaKey(d.getSigningPublicKeyB64())) {
                verifiedDevices++;
            }
        }

        int jwtBits = jwtService.getSigningKeyBits();
        boolean jwtShorSafe = jwtBits >= 256;
        boolean shorResistant = classicalKeys == 0
                && classicalDevices == 0
                && verifiedKeys == keys.size()
                && verifiedDevices == activeDevices
                && jwtShorSafe;

        Map<String, Object> primitives = new LinkedHashMap<>();
        primitives.put("keyEncapsulation", "ML-KEM-768 (NIST FIPS 203)");
        primitives.put("digitalSignatures", "ML-DSA-65 (NIST FIPS 204)");
        primitives.put("symmetricEncryption", "AES-256-GCM (256-bit)");
        primitives.put("keyDerivationAndMac", "HKDF-SHA-256 / HMAC-SHA-256");
        primitives.put("jwtSigning", "HS256 symmetric HMAC-SHA-256 (" + jwtBits + "-bit key, RS256/ES256/none rejected)");

        Map<String, Object> posture = new LinkedHashMap<>();
        posture.put("shorAlgorithmResistant", shorResistant);
        posture.put("totalKeyVersions", keys.size());
        posture.put("verifiedPqcKeyVersions", verifiedKeys);
        posture.put("totalActiveDevices", activeDevices);
        posture.put("verifiedPqcActiveDevices", verifiedDevices);
        posture.put("classicalAsymmetricKeysDetected", classicalKeys + classicalDevices);
        posture.put("jwtSigningKeyBits", jwtBits);
        posture.put("primitives", primitives);
        posture.put("checkedAt", Instant.now());
        return posture;
    }

    public Map<String, Object> verifyShorResilience() {
        Map<String, Object> baseStatus = inspectPqcStatus();
        List<Map<String, Object>> checks = new ArrayList<>();

        // 1. Live ML-KEM-768 (FIPS 203) encapsulate/decapsulate round-trip
        PostQuantumCryptoService.RawKeyPair kemKp = cryptoService.generateMlKem768KeyPair();
        PostQuantumCryptoService.KemEncapsulation encap = cryptoService.encapsulateMlKem768(kemKp.publicKey());
        byte[] decap = cryptoService.decapsulateMlKem768(kemKp.privateKey(), encap.ciphertext());
        boolean kemRoundTripOk = Arrays.equals(encap.sharedSecret(), decap);
        cryptoService.zeroize(kemKp.privateKey(), encap.sharedSecret(), decap);
        checks.add(checkRow("ML-KEM-768 FIPS 203 key exchange round-trip", kemRoundTripOk));

        // 2. Live ML-DSA-65 (FIPS 204) sign/verify round-trip
        PostQuantumCryptoService.RawKeyPair dsaKp = cryptoService.generateMlDsa65KeyPair();
        byte[] sampleMsg = "trustguard-shor-defense-check".getBytes(StandardCharsets.UTF_8);
        byte[] sig = cryptoService.signMlDsa65(dsaKp.privateKey(), sampleMsg);
        boolean dsaOk = cryptoService.verifyMlDsa65(dsaKp.publicKey(), sampleMsg, sig)
                && !cryptoService.verifyMlDsa65(dsaKp.publicKey(), "tampered".getBytes(StandardCharsets.UTF_8), sig);
        cryptoService.zeroize(dsaKp.privateKey());
        checks.add(checkRow("ML-DSA-65 FIPS 204 signature & tamper rejection", dsaOk));

        // 3. Classical RSA-2048 & ECC P-256 public key rejection in KEM path
        boolean rsaRejected = rejectsKemKey(new byte[294]);
        boolean eccRejected = rejectsKemKey(new byte[65]);
        byte[] invalidModulusKem = new byte[PostQuantumCryptoService.ML_KEM_768_PUBLIC_KEY_BYTES];
        Arrays.fill(invalidModulusKem, (byte) 0xFF);
        boolean modulusRejected = rejectsKemKey(invalidModulusKem);
        boolean zeroKeyRejected = rejectsKemKey(new byte[PostQuantumCryptoService.ML_KEM_768_PUBLIC_KEY_BYTES]);
        checks.add(checkRow("Reject classical RSA/ECC & invalid FIPS 203 modulus KEM keys",
                rsaRejected && eccRejected && modulusRejected && zeroKeyRejected));

        // 4. Classical RSA-2048/ECDSA signature rejection in ML-DSA-65 path
        boolean classicalSigRejected = !cryptoService.verifyMlDsa65(dsaKp.publicKey(), sampleMsg, new byte[256])
                && !cryptoService.verifyMlDsa65(new byte[65], sampleMsg, new byte[64]);
        checks.add(checkRow("Reject classical RSA/ECDSA signature downgrade attempts", classicalSigRejected));

        // 5. Reject RS256 / alg=none JWT header confusion attempts
        Base64.Encoder b64u = Base64.getUrlEncoder().withoutPadding();
        String claims = b64u.encodeToString("{\"sub\":\"admin\",\"role\":\"ADMIN\",\"tv\":0,\"exp\":9999999999}".getBytes(StandardCharsets.UTF_8));
        String rs256Header = b64u.encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String noneHeader = b64u.encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        boolean jwtDowngradeBlocked = jwtService.verifyToken(rs256Header + "." + claims + ".ZmFrZXNpZw").isEmpty()
                && jwtService.verifyToken(noneHeader + "." + claims + ".").isEmpty();
        checks.add(checkRow("Reject RS256 / alg=none JWT classical-downgrade headers", jwtDowngradeBlocked));

        boolean allPassed = Boolean.TRUE.equals(baseStatus.get("shorAlgorithmResistant"))
                && checks.stream().allMatch(c -> Boolean.TRUE.equals(c.get("passed")));

        String actor = currentActorOrSystem();
        auditLogService.appendEvent(
                actor,
                "PQC_SHOR_RESILIENCE_VERIFIED",
                "post-quantum-posture",
                "Verified ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), 256-bit+ symmetric MAC/AEAD, "
                        + "and classical-downgrade rejection (" + checks.size() + " checks passed=" + allPassed + ")"
        );

        Map<String, Object> result = new LinkedHashMap<>(baseStatus);
        result.put("verificationPassed", allPassed);
        result.put("checks", checks);
        result.put("verifiedBy", actor);
        return result;
    }

    private boolean validateBase64KemKey(String pkB64) {
        if (pkB64 == null || pkB64.isBlank()) {
            return false;
        }
        try {
            byte[] pk = Base64.getDecoder().decode(pkB64.trim());
            cryptoService.validateMlKem768PublicKey(pk);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private boolean validateBase64DsaKey(String dsaB64) {
        if (dsaB64 == null || dsaB64.isBlank()) {
            return false;
        }
        try {
            byte[] pk = Base64.getDecoder().decode(dsaB64.trim());
            return cryptoService.isValidMlDsa65PublicKey(pk);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private boolean rejectsKemKey(byte[] candidate) {
        try {
            cryptoService.validateMlKem768PublicKey(candidate);
            return false;
        } catch (IllegalArgumentException ex) {
            return true;
        }
    }

    private boolean containsClassicalMarker(String upperAlg) {
        for (String marker : CLASSICAL_ASYMMETRIC_MARKERS) {
            if (upperAlg.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    private Map<String, Object> checkRow(String name, boolean passed) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("check", name);
        m.put("passed", passed);
        return m;
    }

    private String currentActorOrSystem() {
        try {
            return SecurityUtils.currentUsername();
        } catch (Exception ex) {
            return "system";
        }
    }
}
