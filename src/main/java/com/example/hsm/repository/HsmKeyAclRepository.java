package com.example.hsm.repository;

import com.example.hsm.entity.HsmKeyAcl;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Repository for per-key ACL entries. */
public interface HsmKeyAclRepository extends JpaRepository<HsmKeyAcl, UUID> {

    /** Finds the ACL entry for a specific key/principal pair. */
    @Query("SELECT a FROM HsmKeyAcl a WHERE a.hsmKey.id = :keyId AND a.principal.id = :principalId")
    Optional<HsmKeyAcl> findByKeyIdAndPrincipalId(@Param("keyId") UUID keyId,
                                                   @Param("principalId") UUID principalId);

    /** Finds all ACL entries for a given principal. */
    @Query("SELECT a FROM HsmKeyAcl a WHERE a.principal.id = :principalId")
    List<HsmKeyAcl> findByPrincipalId(@Param("principalId") UUID principalId);

    /** Finds all ACL entries for a given key. */
    @Query("SELECT a FROM HsmKeyAcl a WHERE a.hsmKey.id = :keyId")
    List<HsmKeyAcl> findByKeyId(@Param("keyId") UUID keyId);
}
