package com.trustguard.repository;

import com.trustguard.entity.AccessEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AccessEventRepository extends JpaRepository<AccessEventEntity, Long> {
    Optional<AccessEventEntity> findByRequestId(String requestId);
    List<AccessEventEntity> findTop100ByOrderByTimestampUtcDesc();
    long countByDecision(String decision);
}
