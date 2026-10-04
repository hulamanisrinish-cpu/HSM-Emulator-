package com.example.hsm.dto;

import com.example.hsm.entity.HsmAlgorithm;
import com.example.hsm.entity.KeyState;
import com.example.hsm.entity.KeyType;

import java.time.Instant;
import java.util.UUID;

/** Key metadata returned to callers. Never includes wrapped key bytes. */
public record KeyMetadataDto(
        UUID id,
        String name,
        HsmAlgorithm algorithm,
        KeyType keyType,
        KeyState state,
        int version,
        Instant createdAt,
        UUID createdBy
) {}
