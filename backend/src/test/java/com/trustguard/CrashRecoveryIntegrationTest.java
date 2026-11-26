package com.trustguard;

import com.trustguard.dto.AccessCheckRequest;
import com.trustguard.dto.AccessCheckResponse;
import com.trustguard.dto.DeviceEnrolRequest;
import com.trustguard.dto.DeviceResponse;
import com.trustguard.dto.KeyVersionResponse;
import com.trustguard.service.AccessControlService;
import com.trustguard.service.DeviceService;
import com.trustguard.service.KeyManagementService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Simulates crash/restart recovery across two separate Spring application contexts
 * backed by persistent storage, verifying committed key version and device revocation state survive restart.
 */
class CrashRecoveryIntegrationTest {

    @TempDir
    Path tempDir;

    @Test
    void committedKeyVersionAndRevokedDevicePersistAcrossRestart() {
        String dbUrl = "jdbc:h2:file:" + tempDir.resolve("crash-db").toAbsolutePath() + ";MODE=MySQL;DATABASE_TO_LOWER=TRUE";
        String keystorePath = tempDir.resolve("crash-ks.json").toAbsolutePath().toString();

        String[] commonArgs = new String[]{
                "--spring.profiles.active=local",
                "--server.port=0",
                "--spring.datasource.url=" + dbUrl,
                "--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.datasource.username=sa",
                "--spring.datasource.password=",
                "--spring.jpa.hibernate.ddl-auto=update",
                "--trustguard.keystore.path=" + keystorePath,
                "--trustguard.demo.seed-enabled=true"
        };

        int rotatedVersion;
        String revokedDeviceUid;

        // Phase 1: Start instance, rotate key to v2, revoke a device, then stop context (crash/restart)
        try (ConfigurableApplicationContext ctx1 = SpringApplication.run(TrustGuardApplication.class, commonArgs)) {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")))
            );

            KeyManagementService keyService = ctx1.getBean(KeyManagementService.class);
            DeviceService deviceService = ctx1.getBean(DeviceService.class);

            KeyVersionResponse prep = keyService.prepareKey("trustguard-data-key", 0);
            keyService.acknowledgeKey(prep.id(), null);
            KeyVersionResponse committed = keyService.commitKey(prep.id());
            rotatedVersion = committed.versionNumber();
            assertTrue(rotatedVersion >= 2);

            DeviceResponse enrolled = deviceService.enrolDevice(new DeviceEnrolRequest("alice", "Alice Crash Test Device", null));
            revokedDeviceUid = enrolled.deviceUid();
            deviceService.revokeDevice(enrolled.id(), "Crash recovery persistence verification");
        } finally {
            SecurityContextHolder.clearContext();
        }

        // Phase 2: Restart fresh application context against same persisted DB & keystore
        try (ConfigurableApplicationContext ctx2 = SpringApplication.run(TrustGuardApplication.class, commonArgs)) {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")))
            );
            KeyManagementService keyService = ctx2.getBean(KeyManagementService.class);
            DeviceService deviceService = ctx2.getBean(DeviceService.class);

            assertEquals(rotatedVersion, keyService.getActiveCommittedKey().getVersionNumber());
            assertTrue(deviceService.getLatestRevocationVersion() >= 1L);

            DeviceResponse reloaded = deviceService.listDevices().stream()
                    .filter(d -> d.deviceUid().equals(revokedDeviceUid))
                    .findFirst()
                    .orElseThrow();
            assertEquals("REVOKED", reloaded.status());
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void uncommittedRotationRevertsSafelyAcrossCrashRestartLeavingV1Active() {
        String dbUrl = "jdbc:h2:file:" + tempDir.resolve("uncommitted-db").toAbsolutePath() + ";MODE=MySQL;DATABASE_TO_LOWER=TRUE";
        String keystorePath = tempDir.resolve("uncommitted-ks.json").toAbsolutePath().toString();

        String[] commonArgs = new String[]{
                "--spring.profiles.active=local",
                "--server.port=0",
                "--spring.datasource.url=" + dbUrl,
                "--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.datasource.username=sa",
                "--spring.datasource.password=",
                "--spring.jpa.hibernate.ddl-auto=update",
                "--trustguard.keystore.path=" + keystorePath,
                "--trustguard.demo.seed-enabled=true"
        };

        int preparedUncommittedVersion;

        // Phase 1: Prepare key v2 without committing (simulating crash mid-rotation)
        try (ConfigurableApplicationContext ctx1 = SpringApplication.run(TrustGuardApplication.class, commonArgs)) {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")))
            );

            KeyManagementService keyService = ctx1.getBean(KeyManagementService.class);
            assertEquals(1, keyService.getActiveCommittedKey().getVersionNumber());

            KeyVersionResponse prepared = keyService.prepareKey("trustguard-data-key", 0);
            preparedUncommittedVersion = prepared.versionNumber();
            assertEquals(2, preparedUncommittedVersion);
            assertEquals("DISTRIBUTED", prepared.status());
            assertEquals(1, keyService.getActiveCommittedKey().getVersionNumber());
        } finally {
            SecurityContextHolder.clearContext();
        }

        // Phase 2: Restart against same persisted DB & keystore -> v1 remains active committed key, v2 rejected
        try (ConfigurableApplicationContext ctx2 = SpringApplication.run(TrustGuardApplication.class, commonArgs)) {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")))
            );
            KeyManagementService keyService = ctx2.getBean(KeyManagementService.class);
            assertEquals(1, keyService.getActiveCommittedKey().getVersionNumber());

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER")))
            );
            AccessControlService accessService = ctx2.getBean(AccessControlService.class);

            AccessCheckResponse uncommittedAttempt = accessService.checkAccess(new AccessCheckRequest(
                    null, false, null, "portal", "vault", "brief-alice", "read",
                    "node-alpha", preparedUncommittedVersion, false, null, null, "crash-uncommitted-v2"
            ));
            assertEquals("DENY", uncommittedAttempt.decision());
            assertTrue(uncommittedAttempt.reason().toLowerCase().contains("not yet committed"));

            AccessCheckResponse v1Read = accessService.checkAccess(new AccessCheckRequest(
                    null, false, null, "portal", "vault", "brief-alice", "read",
                    "node-alpha", 1, false, null, null, "crash-v1-fallback"
            ));
            assertEquals("ALLOW", v1Read.decision());
            assertEquals(1, v1Read.keyVersionUsed());
            assertNotNull(v1Read.body());
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}
