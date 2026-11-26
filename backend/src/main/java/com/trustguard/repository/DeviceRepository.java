package com.trustguard.repository;

import com.trustguard.entity.DeviceEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface DeviceRepository extends JpaRepository<DeviceEntity, Long> {
    Optional<DeviceEntity> findByDeviceUid(String deviceUid);
    List<DeviceEntity> findByOwnerUsernameOrderByEnrolledAtDesc(String username);
    List<DeviceEntity> findAllByOrderByEnrolledAtDesc();
    long countByStatus(String status);
    Optional<DeviceEntity> findFirstByOwnerUsernameAndStatusOrderByEnrolledAtDesc(String username, String status);
}
