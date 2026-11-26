package com.trustguard.audit;

import com.trustguard.dto.AuditVerifyResponse;
import com.trustguard.entity.AuditLogEntity;
import com.trustguard.exception.ResourceNotFoundException;
import com.trustguard.repository.AuditLogRepository;
import com.trustguard.security.SecurityUtils;
import com.trustguard.util.CanonicalJsonUtil;
import com.trustguard.util.HashUtil;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Calendar;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class AuditLogService {

    public static final String GENESIS_HASH = "0".repeat(64);
    public static final String LIMITATION_NOTICE =
            "Limitation: Because audit rows and their hash chain reside in the same primary database, "
            + "this chain detects tampering by non-privileged editors or partial row alterations, "
            + "but cannot prevent an adversary who compromises the entire database and rewrites all hashes "
            + "or resets trusted external checkpoints.";

    private static final String SELECT_LATEST_SQL =
            "SELECT seq_number, current_hash FROM audit_logs ORDER BY seq_number DESC LIMIT 1";
    private static final String INSERT_AUDIT_SQL =
            "INSERT INTO audit_logs (event_id, seq_number, actor, action, resource, detail, "
                    + "event_timestamp_utc, prev_hash, current_hash, created_at) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private final AuditLogRepository auditLogRepository;
    private final TransactionTemplate requiresNewTx;
    private final HikariDataSource auditDataSource;
    private final boolean auditPoolIsH2;
    private final TransactionTemplate auditTxTemplate;
    private final JdbcTemplate auditJdbcTemplate;
    private final ReentrantLock appendLock = new ReentrantLock(true);
    private final AtomicInteger recordedVerificationFailures = new AtomicInteger(0);

    public AuditLogService(AuditLogRepository auditLogRepository, PlatformTransactionManager transactionManager) {
        this(auditLogRepository, transactionManager, null);
    }

    @Autowired
    public AuditLogService(
            AuditLogRepository auditLogRepository,
            PlatformTransactionManager transactionManager,
            DataSource primaryDataSource
    ) {
        this.auditLogRepository = auditLogRepository;
        this.requiresNewTx = new TransactionTemplate(transactionManager);
        this.requiresNewTx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);

        HikariDataSource dedicatedPool = createDedicatedAuditPool(primaryDataSource);
        this.auditDataSource = dedicatedPool;
        this.auditPoolIsH2 = dedicatedPool != null
                && dedicatedPool.getJdbcUrl().toLowerCase(Locale.ROOT).startsWith("jdbc:h2:");
        if (dedicatedPool != null) {
            this.auditTxTemplate = new TransactionTemplate(new DataSourceTransactionManager(dedicatedPool));
            this.auditJdbcTemplate = new JdbcTemplate(dedicatedPool);
        } else {
            this.auditTxTemplate = null;
            this.auditJdbcTemplate = null;
        }
    }

    @PreDestroy
    public void shutdownAuditPool() {
        if (auditDataSource != null && !auditDataSource.isClosed()) {
            auditDataSource.close();
        }
    }

    private HikariDataSource createDedicatedAuditPool(DataSource primaryDataSource) {
        if (!(primaryDataSource instanceof HikariDataSource hikari)) {
            return null;
        }
        String jdbcUrl = hikari.getJdbcUrl();
        if (jdbcUrl == null || jdbcUrl.isBlank()) {
            return null;
        }
        HikariDataSource pool = new HikariDataSource();
        pool.setPoolName("TrustGuardAuditPool");
        pool.setJdbcUrl(jdbcUrl);
        pool.setUsername(hikari.getUsername());
        pool.setPassword(hikari.getPassword());
        if (hikari.getDriverClassName() != null && !hikari.getDriverClassName().isBlank()) {
            pool.setDriverClassName(hikari.getDriverClassName());
        }
        if (hikari.getDataSourceProperties() != null && !hikari.getDataSourceProperties().isEmpty()) {
            pool.setDataSourceProperties(hikari.getDataSourceProperties());
        }
        pool.setMaximumPoolSize(2);
        pool.setMinimumIdle(1);
        pool.setAutoCommit(false);
        return pool;
    }

    /**
     * Appends a tamper-evident hash-chained audit record on a dedicated connection pool
     * isolated from the primary application pool so outer transactions cannot cause
     * HikariCP exhaustion deadlocks under concurrent load.
     */
    public AuditLogEntity appendEvent(String actor, String action, String resource, String detail) {
        appendLock.lock();
        try {
            if (auditTxTemplate != null && auditJdbcTemplate != null) {
                return auditTxTemplate.execute(status -> insertWithDedicatedJdbc(actor, action, resource, detail));
            }
            return requiresNewTx.execute(status -> {
                AuditLogEntity latest = auditLogRepository.findTopByOrderBySeqNumberDesc().orElse(null);
                long nextSeq = latest == null ? 1L : latest.getSeqNumber() + 1L;
                String prevHash = latest == null ? GENESIS_HASH : latest.getCurrentHash();
                AuditLogEntity entity = buildEntry(nextSeq, prevHash, actor, action, resource, detail);
                return auditLogRepository.save(entity);
            });
        } finally {
            appendLock.unlock();
        }
    }

    private AuditLogEntity insertWithDedicatedJdbc(String actor, String action, String resource, String detail) {
        List<Map<String, Object>> latestRows = auditJdbcTemplate.queryForList(SELECT_LATEST_SQL);
        long nextSeq = 1L;
        String prevHash = GENESIS_HASH;
        if (!latestRows.isEmpty()) {
            Map<String, Object> latest = latestRows.get(0);
            Object seqVal = latest.get("seq_number");
            if (seqVal instanceof Number n) {
                nextSeq = n.longValue() + 1L;
            }
            Object hashVal = latest.get("current_hash");
            if (hashVal != null) {
                prevHash = hashVal.toString();
            }
        }

        AuditLogEntity entity = buildEntry(nextSeq, prevHash, actor, action, resource, detail);
        KeyHolder keyHolder = new GeneratedKeyHolder();

        auditJdbcTemplate.update(con -> {
            PreparedStatement ps = con.prepareStatement(INSERT_AUDIT_SQL, Statement.RETURN_GENERATED_KEYS);
            ps.setString(1, entity.getEventId());
            ps.setLong(2, entity.getSeqNumber());
            ps.setString(3, entity.getActor());
            ps.setString(4, entity.getAction());
            ps.setString(5, entity.getResource());
            ps.setString(6, entity.getDetail());
            bindUtcInstant(ps, 7, entity.getEventTimestampUtc());
            ps.setString(8, entity.getPrevHash());
            ps.setString(9, entity.getCurrentHash());
            bindUtcInstant(ps, 10, entity.getCreatedAt());
            return ps;
        }, keyHolder);

        Number key = keyHolder.getKey();
        if (key != null) {
            entity.setId(key.longValue());
        }
        return entity;
    }

    private void bindUtcInstant(PreparedStatement ps, int index, Instant instant) throws SQLException {
        if (auditPoolIsH2) {
            ps.setObject(index, OffsetDateTime.ofInstant(instant, ZoneOffset.UTC));
        } else {
            ps.setTimestamp(index, Timestamp.from(instant), Calendar.getInstance(TimeZone.getTimeZone("UTC")));
        }
    }

    private AuditLogEntity buildEntry(
            long nextSeq,
            String prevHash,
            String actor,
            String action,
            String resource,
            String detail
    ) {
        String eventId = "aud-" + nextSeq + "-" + UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        AuditLogEntity entity = new AuditLogEntity();
        entity.setEventId(eventId);
        entity.setSeqNumber(nextSeq);
        entity.setActor(truncate(actor, 64));
        entity.setAction(truncate(action, 80));
        entity.setResource(truncate(resource, 128));
        entity.setDetail(truncate(detail, 500));
        entity.setEventTimestampUtc(now);
        entity.setPrevHash(prevHash);
        entity.setCurrentHash(computeHash(entity));
        entity.setCreatedAt(now);
        return entity;
    }

    public AuditVerifyResponse.AuditListResponse listAuditLogs() {
        boolean admin = SecurityUtils.isAdmin();
        String caller = admin ? null : SecurityUtils.currentUsername();
        AuditVerifyResponse globalStatus = verifyChainReadOnly();
        List<AuditVerifyResponse.AuditEntryDto> entries = auditLogRepository.findAllByOrderBySeqNumberDesc()
                .stream()
                .filter(e -> admin || caller.equals(e.getActor()))
                .map(e -> new AuditVerifyResponse.AuditEntryDto(
                        e.getId(),
                        e.getEventId(),
                        e.getSeqNumber(),
                        e.getActor(),
                        e.getAction(),
                        e.getResource(),
                        e.getDetail(),
                        e.getEventTimestampUtc(),
                        e.getPrevHash(),
                        e.getCurrentHash()
                ))
                .toList();
        AuditVerifyResponse scopedVerification = admin
                ? globalStatus
                : new AuditVerifyResponse(
                        globalStatus.valid(),
                        entries.size(),
                        entries.size(),
                        null,
                        null,
                        null,
                        null,
                        globalStatus.valid() ? 0 : 1,
                        "Caller-scoped audit view (" + entries.size() + " entries for " + caller + ")",
                        LIMITATION_NOTICE,
                        globalStatus.verifiedAt()
                );
        return new AuditVerifyResponse.AuditListResponse(entries, scopedVerification);
    }

    public AuditVerifyResponse verifyChain() {
        AuditVerifyResponse result = verifyChainReadOnly();
        if (!result.valid()) {
            recordedVerificationFailures.incrementAndGet();
            return new AuditVerifyResponse(
                    false,
                    result.totalEntries(),
                    result.checkedEntries(),
                    result.firstMismatchSeq(),
                    result.firstMismatchEventId(),
                    result.expectedHash(),
                    result.actualHash(),
                    recordedVerificationFailures.get(),
                    result.message(),
                    result.limitationNotice(),
                    result.verifiedAt()
            );
        }
        return result;
    }

    public AuditVerifyResponse verifyChainReadOnly() {
        List<AuditLogEntity> ordered = auditLogRepository.findAllByOrderBySeqNumberAsc();
        String expectedPrev = GENESIS_HASH;
        long expectedSeq = 1L;
        int checked = 0;

        for (AuditLogEntity entry : ordered) {
            if (entry.getSeqNumber() != expectedSeq || !HashUtil.constantTimeEquals(expectedPrev, entry.getPrevHash())) {
                return new AuditVerifyResponse(
                        false,
                        ordered.size(),
                        checked,
                        entry.getSeqNumber(),
                        entry.getEventId(),
                        expectedPrev,
                        entry.getPrevHash(),
                        recordedVerificationFailures.get(),
                        "Chain link mismatch at sequence #" + entry.getSeqNumber() + " (" + entry.getEventId() + ")",
                        LIMITATION_NOTICE,
                        Instant.now()
                );
            }
            String expectedHash = computeHash(entry);
            checked++;
            if (!HashUtil.constantTimeEquals(expectedHash, entry.getCurrentHash())) {
                return new AuditVerifyResponse(
                        false,
                        ordered.size(),
                        checked,
                        entry.getSeqNumber(),
                        entry.getEventId(),
                        expectedHash,
                        entry.getCurrentHash(),
                        recordedVerificationFailures.get(),
                        "SHA-256 content hash mismatch at sequence #" + entry.getSeqNumber() + " (" + entry.getEventId() + ")",
                        LIMITATION_NOTICE,
                        Instant.now()
                );
            }
            expectedPrev = expectedHash;
            expectedSeq++;
        }

        return new AuditVerifyResponse(
                true,
                ordered.size(),
                checked,
                null,
                null,
                null,
                null,
                recordedVerificationFailures.get(),
                "Verified " + checked + " chained audit records from genesis.",
                LIMITATION_NOTICE,
                Instant.now()
        );
    }

    @Transactional
    public AuditVerifyResponse simulateTamperForDemo(Long seqNumber) {
        List<AuditLogEntity> ordered = auditLogRepository.findAllByOrderBySeqNumberAsc();
        if (ordered.isEmpty()) {
            throw new ResourceNotFoundException("No audit logs available to test tampering");
        }
        AuditLogEntity target = seqNumber == null
                ? ordered.get(ordered.size() - 1)
                : ordered.stream()
                .filter(e -> e.getSeqNumber() == seqNumber)
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("Audit sequence not found: " + seqNumber));

        if (!target.getDetail().endsWith(" [TAMPERED_DEMO]")) {
            target.setDetail(truncate(target.getDetail(), 480) + " [TAMPERED_DEMO]");
            auditLogRepository.save(target);
        }
        return verifyChain();
    }

    @Transactional
    public AuditVerifyResponse revertSimulatedTamperForDemo() {
        List<AuditLogEntity> ordered = auditLogRepository.findAllByOrderBySeqNumberAsc();
        for (AuditLogEntity entry : ordered) {
            if (entry.getDetail().endsWith(" [TAMPERED_DEMO]")) {
                entry.setDetail(entry.getDetail().substring(0, entry.getDetail().length() - " [TAMPERED_DEMO]".length()));
                auditLogRepository.save(entry);
            }
        }
        return verifyChainReadOnly();
    }

    public int getVerificationFailuresCount() {
        return recordedVerificationFailures.get();
    }

    public String computeHash(AuditLogEntity entry) {
        Map<String, Object> canonical = new LinkedHashMap<>();
        canonical.put("seqNumber", entry.getSeqNumber());
        canonical.put("eventId", entry.getEventId());
        canonical.put("actor", entry.getActor());
        canonical.put("action", entry.getAction());
        canonical.put("resource", entry.getResource());
        canonical.put("detail", entry.getDetail());
        canonical.put("eventTimestampUtc", entry.getEventTimestampUtc().truncatedTo(ChronoUnit.MILLIS).toString());
        canonical.put("prevHash", entry.getPrevHash());
        return HashUtil.sha256Hex(CanonicalJsonUtil.toCanonicalJson(canonical));
    }

    private String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max);
    }
}
