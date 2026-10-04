package com.example.hsm.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

/**
 * Per-key ACL entry granting an {@link HsmUser} (AppClient) access to a specific {@link HsmKey}.
 */
@Entity
@Table(name = "hsm_key_acls",
        uniqueConstraints = @UniqueConstraint(name = "uq_acl_key_principal",
                columnNames = {"key_id", "principal_id"}))
public class HsmKeyAcl {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "key_id", nullable = false)
    private HsmKey hsmKey;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "principal_id", nullable = false)
    private HsmUser principal;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private AclPermission permission = AclPermission.ALLOW;

    @Column(name = "granted_at", nullable = false, updatable = false)
    private Instant grantedAt = Instant.now();

    @Column(name = "granted_by")
    private UUID grantedBy;

    protected HsmKeyAcl() {}

    public HsmKeyAcl(HsmKey hsmKey, HsmUser principal, UUID grantedBy) {
        this.hsmKey = hsmKey;
        this.principal = principal;
        this.permission = AclPermission.ALLOW;
        this.grantedAt = Instant.now();
        this.grantedBy = grantedBy;
    }

    public UUID getId() { return id; }
    public HsmKey getHsmKey() { return hsmKey; }
    public HsmUser getPrincipal() { return principal; }
    public AclPermission getPermission() { return permission; }
    public Instant getGrantedAt() { return grantedAt; }
    public UUID getGrantedBy() { return grantedBy; }
}
