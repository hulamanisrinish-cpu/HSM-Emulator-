package com.example.hsm.service.crypto;

/** Holds the output of an AES-256-GCM encryption. */
public record EncryptionResult(byte[] iv, byte[] ciphertext, byte[] authTag) {}
