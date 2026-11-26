package com.trustguard.repository;

import com.trustguard.entity.SecurityAlertEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SecurityAlertRepository extends JpaRepository<SecurityAlertEntity, Long> {
    List<SecurityAlertEntity> findAllByOrderByDetectedAtDesc();
    List<SecurityAlertEntity> findByDatasetSourceOrderByIdAsc(String datasetSource);
    long countByResolvedFalse();
    long countBySeverityAndResolvedFalse(String severity);
    Optional<SecurityAlertEntity> findByAlertUid(String alertUid);
}
