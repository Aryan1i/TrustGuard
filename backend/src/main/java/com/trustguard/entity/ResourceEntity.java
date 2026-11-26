package com.trustguard.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "resources")
public class ResourceEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "resource_key", nullable = false, unique = true, length = 80)
    private String resourceKey;

    @Column(nullable = false, length = 160)
    private String title;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "owner_user_id", nullable = false)
    private UserEntity owner;

    @Column(name = "allowed_services", nullable = false, length = 255)
    private String allowedServices;

    @Column(nullable = false, length = 40)
    private String classification;

    @Column(name = "content_ciphertext_b64", nullable = false, columnDefinition = "TEXT")
    private String contentCiphertextB64;

    @Column(name = "content_iv_b64", nullable = false, length = 64)
    private String contentIvB64;

    @Column(name = "content_aad", nullable = false, length = 255)
    private String contentAad;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "active_key_version_id", nullable = false)
    private KeyVersionEntity activeKeyVersion;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getResourceKey() { return resourceKey; }
    public void setResourceKey(String resourceKey) { this.resourceKey = resourceKey; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public UserEntity getOwner() { return owner; }
    public void setOwner(UserEntity owner) { this.owner = owner; }
    public String getAllowedServices() { return allowedServices; }
    public void setAllowedServices(String allowedServices) { this.allowedServices = allowedServices; }
    public String getClassification() { return classification; }
    public void setClassification(String classification) { this.classification = classification; }
    public String getContentCiphertextB64() { return contentCiphertextB64; }
    public void setContentCiphertextB64(String contentCiphertextB64) { this.contentCiphertextB64 = contentCiphertextB64; }
    public String getContentIvB64() { return contentIvB64; }
    public void setContentIvB64(String contentIvB64) { this.contentIvB64 = contentIvB64; }
    public String getContentAad() { return contentAad; }
    public void setContentAad(String contentAad) { this.contentAad = contentAad; }
    public KeyVersionEntity getActiveKeyVersion() { return activeKeyVersion; }
    public void setActiveKeyVersion(KeyVersionEntity activeKeyVersion) { this.activeKeyVersion = activeKeyVersion; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
