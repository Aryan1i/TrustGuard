package com.trustguard;

import com.trustguard.crypto.PostQuantumCryptoService;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class PostQuantumCryptoServiceTest {

    private final PostQuantumCryptoService crypto = new PostQuantumCryptoService();

    @Test
    void mlKem768RoundTripAndProtectedReadProof() {
        PostQuantumCryptoService.RawKeyPair kp = crypto.generateMlKem768KeyPair();
        assertEquals(1184, kp.publicKey().length);

        PostQuantumCryptoService.KemEncapsulation encap = crypto.encapsulateMlKem768(kp.publicKey());
        assertEquals(1088, encap.ciphertext().length);
        assertEquals(32, encap.sharedSecret().length);

        byte[] decapsulated = crypto.decapsulateMlKem768(kp.privateKey(), encap.ciphertext());
        assertArrayEquals(encap.sharedSecret(), decapsulated);

        String proof1 = crypto.computeProtectedReadProof(encap.sharedSecret(), "chal-1", "demo-body");
        String proof2 = crypto.computeProtectedReadProof(decapsulated, "chal-1", "demo-body");
        assertEquals(proof1, proof2);
        assertEquals(64, proof1.length());
        assertEquals(proof1.toLowerCase(), proof1);
    }

    @Test
    void mlDsa65SignVerifyAndRejectTamper() {
        PostQuantumCryptoService.RawKeyPair kp = crypto.generateMlDsa65KeyPair();
        byte[] msg = "canonical-message".getBytes(StandardCharsets.UTF_8);
        byte[] sig = crypto.signMlDsa65(kp.privateKey(), msg);

        assertTrue(crypto.verifyMlDsa65(kp.publicKey(), msg, sig));
        assertFalse(crypto.verifyMlDsa65(kp.publicKey(), "tampered-message".getBytes(StandardCharsets.UTF_8), sig));
    }

    @Test
    void hkdfAndAesGcmBindAadAndZeroizeSecrets() {
        byte[] ikm = new byte[32];
        Arrays.fill(ikm, (byte) 0x42);
        byte[] key = crypto.hkdfSha256(ikm, "salt".getBytes(StandardCharsets.UTF_8), "info".getBytes(StandardCharsets.UTF_8), 32);
        assertEquals(32, key.length);

        String aad = "{\"recipient\":\"bob\"}";
        PostQuantumCryptoService.AesGcmPayload ct = crypto.encryptAes256Gcm(key, "hello-pq", aad);
        assertEquals("hello-pq", crypto.decryptAes256Gcm(key, ct.ivB64(), ct.ciphertextB64(), aad));
        assertThrows(IllegalArgumentException.class,
                () -> crypto.decryptAes256Gcm(key, ct.ivB64(), ct.ciphertextB64(), "{\"recipient\":\"mallory\"}"));

        crypto.zeroize(ikm, key);
        assertArrayEquals(new byte[32], key);
    }

    @Test
    void shorDefenseRejectsClassicalKeysAndOutOfRangeFips203Modulus() {
        // Reject RSA/ECC sized keys and FIPS 203 invalid modulus/all-zero keys
        assertThrows(IllegalArgumentException.class, () -> crypto.encapsulateMlKem768(new byte[294]));
        assertThrows(IllegalArgumentException.class, () -> crypto.encapsulateMlKem768(new byte[65]));
        assertThrows(IllegalArgumentException.class,
                () -> crypto.encapsulateMlKem768(new byte[PostQuantumCryptoService.ML_KEM_768_PUBLIC_KEY_BYTES]));

        byte[] invalidModulus = new byte[PostQuantumCryptoService.ML_KEM_768_PUBLIC_KEY_BYTES];
        Arrays.fill(invalidModulus, (byte) 0xFF);
        assertThrows(IllegalArgumentException.class, () -> crypto.encapsulateMlKem768(invalidModulus));

        // Reject malformed ciphertext & classical signatures in ML-DSA-65
        PostQuantumCryptoService.RawKeyPair kemKp = crypto.generateMlKem768KeyPair();
        assertThrows(IllegalArgumentException.class, () -> crypto.decapsulateMlKem768(kemKp.privateKey(), new byte[128]));

        PostQuantumCryptoService.RawKeyPair dsaKp = crypto.generateMlDsa65KeyPair();
        byte[] msg = "shor-test".getBytes(StandardCharsets.UTF_8);
        assertFalse(crypto.verifyMlDsa65(dsaKp.publicKey(), msg, new byte[256]));
        assertFalse(crypto.verifyMlDsa65(new byte[294], msg, new byte[PostQuantumCryptoService.ML_DSA_65_SIGNATURE_BYTES]));
    }
}
