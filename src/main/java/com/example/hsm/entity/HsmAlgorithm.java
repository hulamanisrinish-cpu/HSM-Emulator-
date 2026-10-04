package com.example.hsm.entity;

/** Supported key algorithms. */
public enum HsmAlgorithm {
    /** AES-256 symmetric key — used for encrypt/decrypt (AES-256-GCM). */
    AES_256,
    /** RSA-2048 asymmetric key pair — used for sign/verify (SHA256withRSA). */
    RSA_2048,
    /** EC P-256 asymmetric key pair — used for sign/verify (SHA256withECDSA). */
    EC_P256
}
