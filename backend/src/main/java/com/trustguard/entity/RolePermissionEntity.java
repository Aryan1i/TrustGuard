package com.trustguard.entity;

import jakarta.persistence.*;

@Entity
@Table(
        name = "role_permissions",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_role_perm_tuple",
                columnNames = {"role_name", "service_name", "target_service", "action"}
        )
)
public class RolePermissionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "role_name", nullable = false, length = 40)
    private String roleName;

    @Column(name = "service_name", nullable = false, length = 64)
    private String serviceName;

    @Column(name = "target_service", nullable = false, length = 64)
    private String targetService;

    @Column(nullable = false, length = 40)
    private String action;

    @Column(nullable = false)
    private boolean allowed = true;

    @Column(length = 255)
    private String description;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getRoleName() { return roleName; }
    public void setRoleName(String roleName) { this.roleName = roleName; }
    public String getServiceName() { return serviceName; }
    public void setServiceName(String serviceName) { this.serviceName = serviceName; }
    public String getTargetService() { return targetService; }
    public void setTargetService(String targetService) { this.targetService = targetService; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public boolean isAllowed() { return allowed; }
    public void setAllowed(boolean allowed) { this.allowed = allowed; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}
