package com.trustguard.repository;

import com.trustguard.entity.KeyVersionEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface KeyVersionRepository extends JpaRepository<KeyVersionEntity, Long> {
    List<KeyVersionEntity> findAllByOrderByVersionNumberDesc();
    Optional<KeyVersionEntity> findFirstByStatusOrderByVersionNumberDesc(String status);
    Optional<KeyVersionEntity> findByKeyAliasAndVersionNumber(String keyAlias, int versionNumber);
    Optional<KeyVersionEntity> findFirstByKeyAliasOrderByVersionNumberDesc(String keyAlias);
    Optional<KeyVersionEntity> findByVersionNumber(int versionNumber);
}
