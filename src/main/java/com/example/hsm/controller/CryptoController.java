package com.example.hsm.controller;

import com.example.hsm.dto.*;
import com.example.hsm.security.HsmPrincipal;
import com.example.hsm.service.CryptoService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/** REST endpoints for cryptographic operations. AppClient role + per-key ACL required. */
@RestController
@RequestMapping("/api/v1/crypto")
@Tag(name = "Cryptographic Operations", description = "Encrypt/decrypt/sign/verify — AppClient role and ACL required")
public class CryptoController {

    private final CryptoService cryptoService;

    public CryptoController(CryptoService cryptoService) { this.cryptoService = cryptoService; }

    @PostMapping("/encrypt")
    @Operation(summary = "Encrypt plaintext (Base64) using a managed key")
    public EncryptResponse encrypt(@Valid @RequestBody EncryptRequest req,
                                   @AuthenticationPrincipal HsmPrincipal caller) {
        return cryptoService.encrypt(req, caller);
    }

    @PostMapping("/decrypt")
    @Operation(summary = "Decrypt ciphertext (Base64) using a managed key")
    public DecryptResponse decrypt(@Valid @RequestBody DecryptRequest req,
                                   @AuthenticationPrincipal HsmPrincipal caller) {
        return cryptoService.decrypt(req, caller);
    }

    @PostMapping("/sign")
    @Operation(summary = "Sign data (Base64) using a managed asymmetric key")
    public SignResponse sign(@Valid @RequestBody SignRequest req,
                             @AuthenticationPrincipal HsmPrincipal caller) {
        return cryptoService.sign(req, caller);
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify a signature — returns valid=false (not 4xx) on invalid signature")
    public VerifyResponse verify(@Valid @RequestBody VerifyRequest req,
                                 @AuthenticationPrincipal HsmPrincipal caller) {
        return cryptoService.verify(req, caller);
    }
}
