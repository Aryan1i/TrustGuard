package com.trustguard.repository;

import com.trustguard.entity.SimulatedNodeEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SimulatedNodeRepository extends JpaRepository<SimulatedNodeEntity, Long> {
    Optional<SimulatedNodeEntity> findByNodeCode(String nodeCode);
    List<SimulatedNodeEntity> findAllByOrderByIdAsc();
}
