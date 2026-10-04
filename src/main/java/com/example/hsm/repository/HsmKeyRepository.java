package com.example.hsm.repository;

import com.example.hsm.entity.HsmKey;
import com.example.hsm.entity.KeyState;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Repository for {@link HsmKey} entities. */
public interface HsmKeyRepository extends JpaRepository<HsmKey, UUID> {

    /** Finds a key by its unique name. */
    Optional<HsmKey> findByName(String name);

    /** Finds all keys in the given state. */
    List<HsmKey> findByKeyState(KeyState keyState);
}
