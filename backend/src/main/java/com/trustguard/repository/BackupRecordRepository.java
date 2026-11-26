package com.trustguard.repository;

import com.trustguard.entity.BackupRecordEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface BackupRecordRepository extends JpaRepository<BackupRecordEntity, Long> {
    Optional<BackupRecordEntity> findByBackupId(String backupId);
    List<BackupRecordEntity> findAllByOrderByCreatedAtDesc();
}
