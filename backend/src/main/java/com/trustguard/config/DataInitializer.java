package com.trustguard.config;

import com.trustguard.audit.AuditLogService;
import com.trustguard.crypto.PostQuantumCryptoService;
import com.trustguard.crypto.ProtectedKeyStore;
import com.trustguard.detection.DetectionOrchestrationService;
import com.trustguard.entity.DeviceEntity;
import com.trustguard.entity.KeyVersionEntity;
import com.trustguard.entity.NodeKeyAcknowledgementEntity;
import com.trustguard.entity.ResourceEntity;
import com.trustguard.entity.RolePermissionEntity;
import com.trustguard.entity.SimulatedNodeEntity;
import com.trustguard.entity.UserEntity;
import com.trustguard.repository.DeviceRepository;
import com.trustguard.repository.KeyVersionRepository;
import com.trustguard.repository.NodeKeyAcknowledgementRepository;
import com.trustguard.repository.ResourceRepository;
import com.trustguard.repository.RolePermissionRepository;
import com.trustguard.repository.SimulatedNodeRepository;
import com.trustguard.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

@Component
public class DataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);
    private static final String EPHEMERAL_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%";
    private static final int MIN_PROD_SEED_PASSWORD_LEN = 12;

    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final KeyVersionRepository keyVersionRepository;
    private final SimulatedNodeRepository nodeRepository;
    private final NodeKeyAcknowledgementRepository ackRepository;
    private final ResourceRepository resourceRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final PasswordEncoder passwordEncoder;
    private final PostQuantumCryptoService cryptoService;
    private final ProtectedKeyStore keyStore;
    private final AuditLogService auditLogService;
    private final DetectionOrchestrationService detectionService;
    private final Environment environment;
    private final boolean seedEnabled;
    private final String demoPassword;

    public DataInitializer(
            UserRepository userRepository,
            DeviceRepository deviceRepository,
            KeyVersionRepository keyVersionRepository,
            SimulatedNodeRepository nodeRepository,
            NodeKeyAcknowledgementRepository ackRepository,
            ResourceRepository resourceRepository,
            RolePermissionRepository rolePermissionRepository,
            PasswordEncoder passwordEncoder,
            PostQuantumCryptoService cryptoService,
            ProtectedKeyStore keyStore,
            AuditLogService auditLogService,
            DetectionOrchestrationService detectionService,
            Environment environment,
            @Value("${trustguard.demo.seed-enabled:true}") boolean seedEnabled,
            @Value("${trustguard.demo.password:${TRUSTGUARD_DEMO_PASSWORD:}}") String demoPassword
    ) {
        this.userRepository = userRepository;
        this.deviceRepository = deviceRepository;
        this.keyVersionRepository = keyVersionRepository;
        this.nodeRepository = nodeRepository;
        this.ackRepository = ackRepository;
        this.resourceRepository = resourceRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.passwordEncoder = passwordEncoder;
        this.cryptoService = cryptoService;
        this.keyStore = keyStore;
        this.auditLogService = auditLogService;
        this.detectionService = detectionService;
        this.environment = environment;
        this.seedEnabled = seedEnabled;
        this.demoPassword = demoPassword;
    }

    public void validateStartupConfiguration() {
        boolean isDevOrTest = environment != null && Arrays.stream(environment.getActiveProfiles())
                .anyMatch(p -> "local".equalsIgnoreCase(p) || "test".equalsIgnoreCase(p));
        if (!isDevOrTest && seedEnabled
                && (demoPassword == null || demoPassword.isBlank() || demoPassword.trim().length() < MIN_PROD_SEED_PASSWORD_LEN)) {
            throw new IllegalStateException(
                    "Refusing to seed identities outside local/test profiles without explicit "
                            + "TRUSTGUARD_DEMO_PASSWORD (min " + MIN_PROD_SEED_PASSWORD_LEN + " chars) or trustguard.demo.seed-enabled=false"
            );
        }
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        validateStartupConfiguration();
        if (!seedEnabled || userRepository.count() > 0) {
            return;
        }

        String rawPassword = resolveEffectiveSeedPassword();
        String encodedPassword = passwordEncoder.encode(rawPassword);
        UserEntity alice = saveUser("alice", "Alice (Synthetic User)", "alice@synthetic.trustguard.local", "USER", encodedPassword);
        UserEntity bob = saveUser("bob", "Bob (Synthetic User)", "bob@synthetic.trustguard.local", "USER", encodedPassword);
        UserEntity charlie = saveUser("charlie", "Charlie (Synthetic User)", "charlie@synthetic.trustguard.local", "USER", encodedPassword);
        UserEntity admin = saveUser("admin", "Admin (Synthetic Operator)", "admin@synthetic.trustguard.local", "ADMIN", encodedPassword);

        // Seed 3 simulated policy enforcement nodes
        List<SimulatedNodeEntity> nodes = List.of(
                saveNode("node-alpha", "Node Alpha (Primary Edge)", "ap-south-sim", 1),
                saveNode("node-beta", "Node Beta (Replica West)", "eu-west-sim", 1),
                saveNode("node-gamma", "Node Gamma (Replica East)", "us-east-sim", 1)
        );

        // Seed initial committed key v1
        PostQuantumCryptoService.RawKeyPair v1Kem = cryptoService.generateMlKem768KeyPair();
        byte[] v1Dek = cryptoService.generateRandomAes256Key();
        String v1PrivRef = keyStore.storeSecret(
                com.trustguard.service.KeyManagementService.kemPrivSecretId(
                        com.trustguard.service.KeyManagementService.DEFAULT_ALIAS, 1),
                v1Kem.privateKey()
        );
        keyStore.storeSecret(
                com.trustguard.service.KeyManagementService.dekSecretId(
                        com.trustguard.service.KeyManagementService.DEFAULT_ALIAS, 1),
                v1Dek
        );

        Instant now = Instant.now();
        KeyVersionEntity v1 = new KeyVersionEntity();
        v1.setKeyAlias("trustguard-data-key");
        v1.setVersionNumber(1);
        v1.setAlgorithm("ML-KEM-768 + AES-256-GCM");
        v1.setStatus("COMMITTED");
        v1.setPublicKeyB64(Base64.getEncoder().encodeToString(v1Kem.publicKey()));
        v1.setPublicKeyFingerprint(v1Kem.fingerprintSha256());
        v1.setKeyReference(v1PrivRef);
        v1.setGracePeriodSeconds(60);
        v1.setCreatedAt(now);
        v1.setDistributedAt(now);
        v1.setCommittedAt(now);
        v1.setActivationTime(now);
        v1 = keyVersionRepository.save(v1);

        for (SimulatedNodeEntity node : nodes) {
            NodeKeyAcknowledgementEntity ack = new NodeKeyAcknowledgementEntity();
            ack.setKeyVersion(v1);
            ack.setNode(node);
            ack.setAckStatus("ACKNOWLEDGED");
            ack.setAcknowledgedAt(now);
            ack.setDetailMessage("Initial committed key v1 active");
            ackRepository.save(ack);
        }

        // Seed active devices per synthetic user
        seedDevice("dev-alice-01", alice, "Alice Workstation (Synthetic)");
        seedDevice("dev-bob-01", bob, "Bob Laptop (Synthetic)");
        seedDevice("dev-charlie-01", charlie, "Charlie Mobile (Synthetic)");
        seedDevice("dev-admin-01", admin, "Admin Bastion (Synthetic)");

        // Seed encrypted protected resources
        try {
            seedResource("brief-alice", "Alice Q1 Post-Quantum Architecture Brief", alice, "portal,catalog,vault", "CONFIDENTIAL",
                    "Synthetic Brief Body: ML-KEM-768 rollout milestones for Alice.", v1, v1Dek);
            seedResource("ledger-bob", "Bob Synthetic Treasury Ledger", bob, "portal,vault", "RESTRICTED",
                    "Synthetic Ledger Body: Balance invariants verified for Bob.", v1, v1Dek);
            seedResource("compliance-charlie", "Charlie Synthetic Compliance Checklist", charlie, "portal,catalog", "INTERNAL",
                    "Synthetic Compliance Body: Audit trail completeness baseline.", v1, v1Dek);
            seedResource("ops-runbook-admin", "Admin Key Rotation Runbook", admin, "admin-console,vault,identity", "ADMIN_ONLY",
                    "Synthetic Runbook: Quorum acknowledgements required before key commit.", v1, v1Dek);
        } finally {
            cryptoService.zeroize(v1Kem.privateKey(), v1Dek);
        }

        // Seed role-based service-edge permissions
        seedPerm("USER", "portal", "vault", "read", true, "Standard users may read owned vault resources via portal");
        seedPerm("USER", "portal", "catalog", "read", true, "Standard users may read catalog");
        seedPerm("ADMIN", "admin-console", "vault", "read", true, "Admins may inspect vault resources");
        seedPerm("ADMIN", "admin-console", "identity", "read", true, "Admins may inspect identity resources");
        seedPerm("ADMIN", "portal", "vault", "read", true, "Admins may read vault via portal");
        seedPerm("ADMIN", "portal", "catalog", "read", true, "Admins may read catalog via portal");

        auditLogService.appendEvent(
                "system",
                "SYSTEM_SEEDED",
                "trustguard-platform",
                "Initialized synthetic users (alice, bob, charlie, admin), 3 simulated nodes, and ML-KEM-768 key v1"
        );

        // Evaluate 22-event practice dataset cleanly at startup (without labels in detector)
        detectionService.evaluatePracticeDataset();
    }

    private String resolveEffectiveSeedPassword() {
        if (demoPassword != null && !demoPassword.isBlank()) {
            return demoPassword;
        }
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(24);
        for (int i = 0; i < 24; i++) {
            sb.append(EPHEMERAL_ALPHABET.charAt(random.nextInt(EPHEMERAL_ALPHABET.length())));
        }
        String generated = sb.toString();
        log.info("Generated ephemeral local demo password for seeded synthetic users (set TRUSTGUARD_DEMO_PASSWORD to use a fixed local password): {}", generated);
        return generated;
    }

    private UserEntity saveUser(String username, String displayName, String email, String role, String encodedPassword) {
        UserEntity u = new UserEntity();
        u.setUsername(username);
        u.setDisplayName(displayName);
        u.setEmail(email);
        u.setRole(role);
        u.setPasswordHash(encodedPassword);
        u.setActive(true);
        return userRepository.save(u);
    }

    private SimulatedNodeEntity saveNode(String code, String name, String region, int keyVersion) {
        SimulatedNodeEntity n = new SimulatedNodeEntity();
        n.setNodeCode(code);
        n.setNodeName(name);
        n.setRegion(region);
        n.setStatus("ONLINE");
        n.setCurrentKeyVersion(keyVersion);
        n.setCurrentRevocationVersion(0L);
        n.setLastHeartbeatAt(Instant.now());
        return nodeRepository.save(n);
    }

    private void seedDevice(String deviceUid, UserEntity owner, String deviceName) {
        PostQuantumCryptoService.RawKeyPair kem = cryptoService.generateMlKem768KeyPair();
        PostQuantumCryptoService.RawKeyPair dsa = cryptoService.generateMlDsa65KeyPair();
        String ref = keyStore.storeSecret(deviceUid + "-kem-priv", kem.privateKey());
        keyStore.storeSecret(deviceUid + "-dsa-priv", dsa.privateKey());
        cryptoService.zeroize(kem.privateKey(), dsa.privateKey());

        DeviceEntity d = new DeviceEntity();
        d.setDeviceUid(deviceUid);
        d.setOwner(owner);
        d.setDeviceName(deviceName);
        d.setPublicKeyB64(Base64.getEncoder().encodeToString(kem.publicKey()));
        d.setPublicKeyFingerprint(kem.fingerprintSha256());
        d.setKeyReference(ref);
        d.setKeyAlgorithm("ML-KEM-768 / ML-DSA-65");
        d.setSigningPublicKeyB64(Base64.getEncoder().encodeToString(dsa.publicKey()));
        d.setStatus("ACTIVE");
        d.setEnrolledAt(Instant.now());
        d.setLastSeenAt(Instant.now());
        deviceRepository.save(d);
    }

    private void seedResource(
            String key,
            String title,
            UserEntity owner,
            String allowedServices,
            String classification,
            String plaintextBody,
            KeyVersionEntity keyVersion,
            byte[] dek
    ) {
        String aad = "resource=" + key + ";owner=" + owner.getUsername();
        PostQuantumCryptoService.AesGcmPayload encrypted = cryptoService.encryptAes256Gcm(dek, plaintextBody, aad);
        ResourceEntity r = new ResourceEntity();
        r.setResourceKey(key);
        r.setTitle(title);
        r.setOwner(owner);
        r.setAllowedServices(allowedServices);
        r.setClassification(classification);
        r.setContentCiphertextB64(encrypted.ciphertextB64());
        r.setContentIvB64(encrypted.ivB64());
        r.setContentAad(aad);
        r.setActiveKeyVersion(keyVersion);
        resourceRepository.save(r);
    }

    private void seedPerm(String role, String src, String dst, String action, boolean allowed, String desc) {
        RolePermissionEntity p = new RolePermissionEntity();
        p.setRoleName(role);
        p.setServiceName(src);
        p.setTargetService(dst);
        p.setAction(action);
        p.setAllowed(allowed);
        p.setDescription(desc);
        rolePermissionRepository.save(p);
    }
}
