package com.example.hsm.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * An HSM user principal with a hashed API token and a single role.
 *
 * <p><strong>Security note:</strong> {@code tokenHash} is excluded from {@link #toString()}
 * to prevent accidental leakage via logs or exception messages.
 */
@Entity
@Table(name = "hsm_users")
public class HsmUser {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 128)
    private String username;

    /** Argon2id hash of the bearer token. Never expose the raw value. */
    @Column(name = "token_hash", nullable = false, length = 512)
    private String tokenHash;

    /** First 16 characters of the token — used as a non-secret fast-lookup index. */
    @Column(name = "token_prefix", length = 16)
    private String tokenPrefix;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private HsmRole role;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private boolean enabled = true;

    protected HsmUser() {}

    public HsmUser(String username, String tokenHash, String tokenPrefix, HsmRole role) {
        this.username = username;
        this.tokenHash = tokenHash;
        this.tokenPrefix = tokenPrefix;
        this.role = role;
        this.createdAt = Instant.now();
        this.enabled = true;
    }

    public UUID getId() { return id; }
    public String getUsername() { return username; }
    public String getTokenHash() { return tokenHash; }
    public String getTokenPrefix() { return tokenPrefix; }
    public HsmRole getRole() { return role; }
    public void setRole(HsmRole role) { this.role = role; }
    public Instant getCreatedAt() { return createdAt; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    /** Deliberately excludes tokenHash to prevent leakage in logs. */
    @Override
    public String toString() {
        return "HsmUser{id=" + id + ", username='" + username + "', role=" + role + ", enabled=" + enabled + "}";
    }
}
