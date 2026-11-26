package com.trustguard.repository;

import com.trustguard.entity.RevocationEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RevocationRepository extends JpaRepository<RevocationEntity, Long> {
    Optional<RevocationEntity> findTopByOrderByRevocationVersionDesc();
    List<RevocationEntity> findAllByOrderByRevocationVersionDesc();
}
