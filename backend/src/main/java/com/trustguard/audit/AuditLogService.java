package com.trustguard.audit;

import com.trustguard.dto.AuditVerifyResponse;
import com.trustguard.entity.AuditLogEntity;
import com.trustguard.exception.ResourceNotFoundException;
import com.trustguard.repository.AuditLogRepository;
import com.trustguard.util.CanonicalJsonUtil;
import com.trustguard.util.HashUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class AuditLogService {

    public static final String GENESIS_HASH = "0".repeat(64);
    public static final String LIMITATION_NOTICE =
            "Limitation: Because audit rows and their hash chain reside in the same primary database, "
            + "this chain detects tampering by non-privileged editors or partial row alterations, "
            + "but cannot prevent an adversary who compromises the entire database and rewrites all hashes "
            + "or resets trusted external checkpoints.";

    private final AuditLogRepository auditLogRepository;
    private final AtomicInteger recordedVerificationFailures = new AtomicInteger(0);

    public AuditLogService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Transactional
    public synchronized AuditLogEntity appendEvent(String actor, String action, String resource, String detail) {
        AuditLogEntity latest = auditLogRepository.findTopByOrderBySeqNumberDesc().orElse(null);
        long nextSeq = latest == null ? 1L : latest.getSeqNumber() + 1L;
        String prevHash = latest == null ? GENESIS_HASH : latest.getCurrentHash();
        String eventId = "aud-" + nextSeq + "-" + UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        AuditLogEntity entity = new AuditLogEntity();
        entity.setEventId(eventId);
        entity.setSeqNumber(nextSeq);
        entity.setActor(actor);
        entity.setAction(action);
        entity.setResource(resource);
        entity.setDetail(truncate(detail, 500));
        entity.setEventTimestampUtc(now);
        entity.setPrevHash(prevHash);
        entity.setCurrentHash(computeHash(entity));
        entity.setCreatedAt(now);
        return auditLogRepository.save(entity);
    }

    public AuditVerifyResponse.AuditListResponse listAuditLogs() {
        List<AuditVerifyResponse.AuditEntryDto> entries = auditLogRepository.findAllByOrderBySeqNumberDesc()
                .stream()
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
        return new AuditVerifyResponse.AuditListResponse(entries, verifyChainReadOnly());
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
