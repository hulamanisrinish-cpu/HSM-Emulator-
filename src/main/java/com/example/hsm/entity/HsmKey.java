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
 * Persisted metadata and wrapped DEK for a cryptographic key managed by the HSM emulator.
 *
 * <p><strong>Security notes:</strong>
 * <ul>
 *   <li>{@code wrappedDek}, {@code ivDek}, and {@code authTagDek} contain the AES-256-GCM
 *       wrapped key material. They are excluded from {@link #toString()}.</li>
 *   <li>Raw key bytes are NEVER stored here; only the wrapped (encrypted) form.</li>
 *   <li>On key destruction, all three byte arrays are overwritten with zeros before save.</li>
 * </ul>
 */
@Entity
@Table(name = "hsm_keys")
public class HsmKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 256)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private HsmAlgorithm algorithm;

    @Enumerated(EnumType.STRING)
    @Column(name = "key_state", nullable = false, length = 16)
    private KeyState keyState = KeyState.ACTIVE;

    @Column(nullable = false)
    private int version = 1;

    /** AES-256-GCM wrapped key material — never expose raw bytes. */
    @Column(name = "wrapped_dek", nullable = false, columnDefinition = "BYTEA")
    private byte[] wrappedDek;

    /** IV used when wrapping the DEK. */
    @Column(name = "iv_dek", nullable = false, columnDefinition = "BYTEA")
    private byte[] ivDek;

    /** GCM authentication tag from the DEK wrapping operation. */
    @Column(name = "auth_tag_dek", nullable = false, columnDefinition = "BYTEA")
    private byte[] authTagDek;

    /** X.509-encoded public key for asymmetric keys — null for symmetric keys. */
    @Column(name = "public_key_bytes", columnDefinition = "BYTEA")
    private byte[] publicKeyBytes;

    @Enumerated(EnumType.STRING)
    @Column(name = "key_type", nullable = false, length = 16)
    private KeyType keyType;

    @Column(name = "created_by")
    private UUID createdBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "last_rotated_at")
    private Instant lastRotatedAt;

    @Column(name = "disabled_at")
    private Instant disabledAt;

    @Column(name = "destroyed_at")
    private Instant destroyedAt;

    protected HsmKey() {}

    public UUID getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public HsmAlgorithm getAlgorithm() { return algorithm; }
    public void setAlgorithm(HsmAlgorithm algorithm) { this.algorithm = algorithm; }
    public KeyState getKeyState() { return keyState; }
    public void setKeyState(KeyState keyState) { this.keyState = keyState; }
    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }
    public byte[] getWrappedDek() { return wrappedDek; }
    public void setWrappedDek(byte[] wrappedDek) { this.wrappedDek = wrappedDek; }
    public byte[] getIvDek() { return ivDek; }
    public void setIvDek(byte[] ivDek) { this.ivDek = ivDek; }
    public byte[] getAuthTagDek() { return authTagDek; }
    public void setAuthTagDek(byte[] authTagDek) { this.authTagDek = authTagDek; }
    public byte[] getPublicKeyBytes() { return publicKeyBytes; }
    public void setPublicKeyBytes(byte[] publicKeyBytes) { this.publicKeyBytes = publicKeyBytes; }
    public KeyType getKeyType() { return keyType; }
    public void setKeyType(KeyType keyType) { this.keyType = keyType; }
    public UUID getCreatedBy() { return createdBy; }
    public void setCreatedBy(UUID createdBy) { this.createdBy = createdBy; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastRotatedAt() { return lastRotatedAt; }
    public void setLastRotatedAt(Instant lastRotatedAt) { this.lastRotatedAt = lastRotatedAt; }
    public Instant getDisabledAt() { return disabledAt; }
    public void setDisabledAt(Instant disabledAt) { this.disabledAt = disabledAt; }
    public Instant getDestroyedAt() { return destroyedAt; }
    public void setDestroyedAt(Instant destroyedAt) { this.destroyedAt = destroyedAt; }

    /** Deliberately excludes wrappedDek, ivDek, authTagDek to prevent leakage in logs. */
    @Override
    public String toString() {
        return "HsmKey{id=" + id + ", name='" + name + "', algorithm=" + algorithm
                + ", state=" + keyState + ", version=" + version + ", keyType=" + keyType + "}";
    }

    /** Builder-style factory for clean construction in service layer. */
    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private final HsmKey key = new HsmKey();

        public Builder name(String name) { key.name = name; return this; }
        public Builder algorithm(HsmAlgorithm alg) { key.algorithm = alg; return this; }
        public Builder keyState(KeyState state) { key.keyState = state; return this; }
        public Builder version(int v) { key.version = v; return this; }
        public Builder wrappedDek(byte[] w) { key.wrappedDek = w; return this; }
        public Builder ivDek(byte[] iv) { key.ivDek = iv; return this; }
        public Builder authTagDek(byte[] tag) { key.authTagDek = tag; return this; }
        public Builder keyType(KeyType t) { key.keyType = t; return this; }
        public Builder createdBy(UUID id) { key.createdBy = id; return this; }
        public HsmKey build() {
            key.createdAt = Instant.now();
            return key;
        }
    }
}
