package com.trustguard.repository;

import com.trustguard.entity.AuditLogEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AuditLogRepository extends JpaRepository<AuditLogEntity, Long> {
    Optional<AuditLogEntity> findTopByOrderBySeqNumberDesc();
    List<AuditLogEntity> findAllByOrderBySeqNumberAsc();
    List<AuditLogEntity> findAllByOrderBySeqNumberDesc();
    Optional<AuditLogEntity> findByEventId(String eventId);
}
