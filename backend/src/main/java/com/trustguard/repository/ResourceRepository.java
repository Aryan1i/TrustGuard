package com.trustguard.repository;

import com.trustguard.entity.ResourceEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ResourceRepository extends JpaRepository<ResourceEntity, Long> {
    Optional<ResourceEntity> findByResourceKey(String resourceKey);
    List<ResourceEntity> findAllByOrderByIdAsc();
    List<ResourceEntity> findByOwnerUsernameOrderByIdAsc(String username);
}
