package com.trustguard.repository;

import com.trustguard.entity.RolePermissionEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RolePermissionRepository extends JpaRepository<RolePermissionEntity, Long> {
    Optional<RolePermissionEntity> findByRoleNameAndServiceNameAndTargetServiceAndAction(
            String roleName, String serviceName, String targetService, String action
    );
    List<RolePermissionEntity> findByRoleName(String roleName);
}
