package com.example.hsm.repository;

import com.example.hsm.entity.HsmConfig;
import org.springframework.data.jpa.repository.JpaRepository;

/** Repository for persistent HSM configuration values (e.g. PBKDF2 salt). */
public interface HsmConfigRepository extends JpaRepository<HsmConfig, Long> {

    /** Finds a config entry by its logical key name. */
    java.util.Optional<HsmConfig> findByConfigKey(String configKey);
}
