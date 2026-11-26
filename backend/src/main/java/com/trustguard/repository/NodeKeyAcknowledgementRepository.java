package com.trustguard.repository;

import com.trustguard.entity.NodeKeyAcknowledgementEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface NodeKeyAcknowledgementRepository extends JpaRepository<NodeKeyAcknowledgementEntity, Long> {
    List<NodeKeyAcknowledgementEntity> findByKeyVersionIdOrderByNodeIdAsc(Long keyVersionId);
    Optional<NodeKeyAcknowledgementEntity> findByKeyVersionIdAndNodeId(Long keyVersionId, Long nodeId);
}
