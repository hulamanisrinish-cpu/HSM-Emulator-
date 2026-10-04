package com.example.hsm.repository;

import com.example.hsm.entity.HsmUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Repository for {@link HsmUser} entities. */
public interface HsmUserRepository extends JpaRepository<HsmUser, UUID> {

    /** Finds an enabled user by username. */
    Optional<HsmUser> findByUsername(String username);

    /** Fast lookup by token prefix for authentication filter. */
    Optional<HsmUser> findByTokenPrefix(String tokenPrefix);

    /** Returns all enabled users. */
    List<HsmUser> findByEnabledTrue();
}
