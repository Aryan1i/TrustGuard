package com.trustguard.service;

import com.trustguard.entity.SecurityAlertEntity;
import com.trustguard.repository.SecurityAlertRepository;
import com.trustguard.util.CanonicalJsonUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

@Service
public class SecurityPersistenceService {

    private final TransactionTemplate requiresNewTx;
    private final TransactionTemplate requiredTx;
    private final SecurityAlertRepository alertRepository;

    public SecurityPersistenceService(
            PlatformTransactionManager transactionManager,
            SecurityAlertRepository alertRepository
    ) {
        this.alertRepository = alertRepository;

        this.requiresNewTx = new TransactionTemplate(transactionManager);
        this.requiresNewTx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);

        this.requiredTx = new TransactionTemplate(transactionManager);
        this.requiredTx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRED);
    }

    public <T> T inRequiresNew(Supplier<T> action) {
        return requiresNewTx.execute(status -> action.get());
    }

    public void runInRequiresNew(Runnable action) {
        requiresNewTx.executeWithoutResult(status -> action.run());
    }

    public <T> T inTransaction(Supplier<T> action) {
        return requiredTx.execute(status -> action.get());
    }

    public SecurityAlertEntity recordLiveAlertInNewTx(
            String prefix,
            String ruleName,
            String severity,
            String outcomeClassification,
            String actor,
            String servicePath,
            String eventId,
            String explanation
    ) {
        String safeActor = truncate(actor, 64);
        String safeRule = truncate(ruleName, 80);
        String safePath = truncate(servicePath, 255);
        Instant now = Instant.now();

        return requiresNewTx.execute(status -> {
            SecurityAlertEntity alert = new SecurityAlertEntity();
            alert.setAlertUid(prefix + "-" + UUID.randomUUID().toString().substring(0, 10));
            alert.setRuleName(safeRule);
            alert.setSeverity(severity);
            alert.setOutcomeClassification(outcomeClassification);
            alert.setActor(safeActor);
            alert.setServicePath(safePath);
            alert.setEventIdsJson(CanonicalJsonUtil.toCanonicalJson(List.of(eventId)));
            alert.setDetectedAt(now);
            alert.setSourceEventTimeUtc(now);
            alert.setDetectionLatencyMs(1L);
            alert.setExplanation(explanation);
            alert.setDatasetSource("LIVE_RUNTIME");
            return alertRepository.save(alert);
        });
    }

    private String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max);
    }
}
