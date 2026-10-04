package com.example.hsm.service.crypto;

/** Holds the AES-GCM wrapped result of a key encryption operation. */
public record WrappedKey(byte[] wrappedDek, byte[] iv, byte[] authTag) {}
