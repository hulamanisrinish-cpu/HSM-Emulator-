package com.example.hsm.controller;

import com.example.hsm.dto.AclRequest;
import com.example.hsm.dto.GenerateKeyRequest;
import com.example.hsm.dto.KeyMetadataDto;
import com.example.hsm.security.HsmPrincipal;
import com.example.hsm.service.KeyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/** REST endpoints for key lifecycle management. CryptoOfficer role required for mutations. */
@RestController
@RequestMapping("/api/v1/keys")
@Tag(name = "Key Management", description = "Key lifecycle operations — CryptoOfficer role required for mutations")
public class KeyController {

    private final KeyService keyService;

    public KeyController(KeyService keyService) { this.keyService = keyService; }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Generate a new cryptographic key")
    public KeyMetadataDto generateKey(@Valid @RequestBody GenerateKeyRequest req,
                                      @AuthenticationPrincipal HsmPrincipal caller) {
        return keyService.generateKey(req, caller);
    }

    @GetMapping
    @Operation(summary = "List accessible keys")
    public List<KeyMetadataDto> listKeys(@AuthenticationPrincipal HsmPrincipal caller) {
        return keyService.listKeys(caller);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get key metadata by ID")
    public KeyMetadataDto getKey(@PathVariable UUID id, @AuthenticationPrincipal HsmPrincipal caller) {
        return keyService.getKeyById(id, caller);
    }

    @PostMapping("/{id}/rotate")
    @Operation(summary = "Rotate a key — generates new version, disables current")
    public KeyMetadataDto rotateKey(@PathVariable UUID id, @AuthenticationPrincipal HsmPrincipal caller) {
        return keyService.rotateKey(id, caller);
    }

    @PatchMapping("/{id}/disable")
    @Operation(summary = "Disable an active key")
    public KeyMetadataDto disableKey(@PathVariable UUID id, @AuthenticationPrincipal HsmPrincipal caller) {
        return keyService.disableKey(id, caller);
    }

    @PatchMapping("/{id}/enable")
    @Operation(summary = "Re-enable a disabled key")
    public KeyMetadataDto enableKey(@PathVariable UUID id, @AuthenticationPrincipal HsmPrincipal caller) {
        return keyService.enableKey(id, caller);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Permanently destroy a key — irreversible")
    public KeyMetadataDto destroyKey(@PathVariable UUID id, @AuthenticationPrincipal HsmPrincipal caller) {
        return keyService.destroyKey(id, caller);
    }

    @PostMapping("/{id}/acl")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Grant AppClient access to a key")
    public void grantAcl(@PathVariable UUID id, @Valid @RequestBody AclRequest req,
                         @AuthenticationPrincipal HsmPrincipal caller) {
        keyService.grantAcl(id, req, caller);
    }

    @DeleteMapping("/{id}/acl/{principalId}")
    @Operation(summary = "Revoke AppClient access to a key")
    public void revokeAcl(@PathVariable UUID id, @PathVariable UUID principalId,
                           @AuthenticationPrincipal HsmPrincipal caller) {
        keyService.revokeAcl(id, principalId, caller);
    }
}
