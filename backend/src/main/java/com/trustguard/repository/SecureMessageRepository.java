package com.trustguard.repository;

import com.trustguard.entity.SecureMessageEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SecureMessageRepository extends JpaRepository<SecureMessageEntity, Long> {
    Optional<SecureMessageEntity> findByMessageId(String messageId);
    List<SecureMessageEntity> findAllByOrderByCreatedAtDesc();
}
