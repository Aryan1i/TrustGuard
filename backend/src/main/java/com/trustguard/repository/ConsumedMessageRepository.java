package com.trustguard.repository;

import com.trustguard.entity.ConsumedMessageEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ConsumedMessageRepository extends JpaRepository<ConsumedMessageEntity, Long> {
    boolean existsByMessageId(String messageId);
    Optional<ConsumedMessageEntity> findByMessageId(String messageId);
}
