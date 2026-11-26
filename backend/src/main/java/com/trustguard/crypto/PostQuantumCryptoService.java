package com.trustguard.crypto;

import com.trustguard.util.HashUtil;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

/**
 * Vetted post-quantum & symmetric cryptography service backed by BouncyCastle 1.80:
 * - ML-KEM-768 (NIST FIPS 203) key encapsulation
 * - ML-DSA-65 (NIST FIPS 204) post-quantum signatures
 * - HKDF-SHA-256 key derivation
 * - AES-256-GCM authenticated encryption
 * - HMAC-SHA-256 challenge proofs
 */
@Service
public class PostQuantumCryptoService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final int AES_GCM_TAG_BITS = 128;
    private static final int AES_GCM_IV_BYTES = 12;
    public static final int ML_KEM_768_PUBLIC_KEY_BYTES = 1184;

    private final SecureRandom secureRandom = new SecureRandom();

    public record RawKeyPair(byte[] publicKey, byte[] privateKey, String fingerprintSha256) {
    }

    public record KemEncapsulation(byte[] ciphertext, byte[] sharedSecret) {
    }

    public record AesGcmPayload(String ivB64, String ciphertextB64) {
    }

    public RawKeyPair generateMlKem768KeyPair() {
        MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
        generator.init(new MLKEMKeyGenerationParameters(secureRandom, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        byte[] pk = ((MLKEMPublicKeyParameters) pair.getPublic()).getEncoded();
        byte[] sk = ((MLKEMPrivateKeyParameters) pair.getPrivate()).getEncoded();
        return new RawKeyPair(pk, sk, HashUtil.sha256Hex(pk));
    }

    public KemEncapsulation encapsulateMlKem768(byte[] rawPublicKey) {
        if (rawPublicKey == null || rawPublicKey.length != ML_KEM_768_PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("Invalid ML-KEM-768 raw public key length");
        }
        MLKEMPublicKeyParameters pubParams = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, rawPublicKey);
        MLKEMGenerator kemGenerator = new MLKEMGenerator(secureRandom);
        SecretWithEncapsulation encapsulated = kemGenerator.generateEncapsulated(pubParams);
        return new KemEncapsulation(encapsulated.getEncapsulation(), encapsulated.getSecret());
    }

    public byte[] decapsulateMlKem768(byte[] rawPrivateKey, byte[] ciphertext) {
        MLKEMPrivateKeyParameters privParams = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, rawPrivateKey);
        MLKEMExtractor extractor = new MLKEMExtractor(privParams);
        return extractor.extractSecret(ciphertext);
    }

    public RawKeyPair generateMlDsa65KeyPair() {
        MLDSAKeyPairGenerator generator = new MLDSAKeyPairGenerator();
        generator.init(new MLDSAKeyGenerationParameters(secureRandom, MLDSAParameters.ml_dsa_65));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        byte[] pk = ((MLDSAPublicKeyParameters) pair.getPublic()).getEncoded();
        byte[] sk = ((MLDSAPrivateKeyParameters) pair.getPrivate()).getEncoded();
        return new RawKeyPair(pk, sk, HashUtil.sha256Hex(pk));
    }

    public byte[] signMlDsa65(byte[] rawPrivateKey, byte[] message) {
        try {
            MLDSAPrivateKeyParameters privParams = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, rawPrivateKey);
            MLDSASigner signer = new MLDSASigner();
            signer.init(true, privParams);
            signer.update(message, 0, message.length);
            return signer.generateSignature();
        } catch (Exception e) {
            throw new IllegalStateException("ML-DSA-65 signature generation failed", e);
        }
    }

    public boolean verifyMlDsa65(byte[] rawPublicKey, byte[] message, byte[] signature) {
        try {
            MLDSAPublicKeyParameters pubParams = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, rawPublicKey);
            MLDSASigner verifier = new MLDSASigner();
            verifier.init(false, pubParams);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        } catch (Exception e) {
            return false;
        }
    }

    public byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int outLengthBytes) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, salt, info));
        byte[] okm = new byte[outLengthBytes];
        hkdf.generateBytes(okm, 0, outLengthBytes);
        return okm;
    }

    public byte[] generateRandomAes256Key() {
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        return key;
    }

    public AesGcmPayload encryptAes256Gcm(byte[] key32, String plaintextUtf8, String aadUtf8) {
        try {
            byte[] iv = new byte[AES_GCM_IV_BYTES];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key32, "AES"), new GCMParameterSpec(AES_GCM_TAG_BITS, iv));
            if (aadUtf8 != null) {
                cipher.updateAAD(aadUtf8.getBytes(StandardCharsets.UTF_8));
            }
            byte[] ct = cipher.doFinal(plaintextUtf8.getBytes(StandardCharsets.UTF_8));
            return new AesGcmPayload(
                    Base64.getEncoder().encodeToString(iv),
                    Base64.getEncoder().encodeToString(ct)
            );
        } catch (Exception e) {
            throw new IllegalStateException("AES-256-GCM encryption failed", e);
        }
    }

    public String decryptAes256Gcm(byte[] key32, String ivB64, String ciphertextB64, String aadUtf8) {
        try {
            byte[] iv = Base64.getDecoder().decode(ivB64);
            byte[] ct = Base64.getDecoder().decode(ciphertextB64);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key32, "AES"), new GCMParameterSpec(AES_GCM_TAG_BITS, iv));
            if (aadUtf8 != null) {
                cipher.updateAAD(aadUtf8.getBytes(StandardCharsets.UTF_8));
            }
            byte[] plain = cipher.doFinal(ct);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalArgumentException("AES-256-GCM authentication or decryption failed", e);
        }
    }

    public String computeProtectedReadProof(byte[] sharedSecret, String challenge, String body) {
        byte[] payload = (challenge + body).getBytes(StandardCharsets.UTF_8);
        return HashUtil.hmacSha256Hex(sharedSecret, payload);
    }

    public void zeroize(byte[]... buffers) {
        if (buffers == null) {
            return;
        }
        for (byte[] buf : buffers) {
            if (buf != null) {
                Arrays.fill(buf, (byte) 0);
            }
        }
    }
}
