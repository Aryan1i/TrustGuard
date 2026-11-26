package com.trustguard.repository;

import com.trustguard.entity.SessionRecordEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SessionRecordRepository extends JpaRepository<SessionRecordEntity, Long> {
    Optional<SessionRecordEntity> findBySessionId(String sessionId);
    List<SessionRecordEntity> findAllByOrderByCreatedAtDesc();
    List<SessionRecordEntity> findByActorUsernameOrderByCreatedAtDesc(String actorUsername);
}
