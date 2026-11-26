package com.trustguard.repository;

import com.trustguard.entity.BackupItemEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BackupItemRepository extends JpaRepository<BackupItemEntity, Long> {
    List<BackupItemEntity> findByBackupRecordId(Long backupRecordId);
}
