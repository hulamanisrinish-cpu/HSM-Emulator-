package com.example.hsm.controller;

import com.example.hsm.dto.CreateUserRequest;
import com.example.hsm.dto.CreateUserResponse;
import com.example.hsm.dto.UserDto;
import com.example.hsm.entity.HsmRole;
import com.example.hsm.security.HsmPrincipal;
import com.example.hsm.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/** REST endpoints for user and role management. Admin role required. */
@RestController
@RequestMapping("/api/v1/users")
@Tag(name = "User Management", description = "User and role management — Admin role required")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) { this.userService = userService; }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a new HSM user and issue a one-time bearer token")
    public CreateUserResponse createUser(@Valid @RequestBody CreateUserRequest req,
                                         @AuthenticationPrincipal HsmPrincipal caller) {
        return userService.createUser(req, caller);
    }

    @GetMapping
    @Operation(summary = "List all users — never includes tokens")
    public List<UserDto> listUsers(@AuthenticationPrincipal HsmPrincipal caller) {
        return userService.listUsers(caller);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Disable a user (revokes authentication)")
    public UserDto disableUser(@PathVariable UUID id, @AuthenticationPrincipal HsmPrincipal caller) {
        return userService.disableUser(id, caller);
    }

    @PostMapping("/{id}/roles/{role}")
    @Operation(summary = "Assign a role to a user")
    public UserDto assignRole(@PathVariable UUID id, @PathVariable HsmRole role,
                              @AuthenticationPrincipal HsmPrincipal caller) {
        return userService.assignRole(id, role, caller);
    }

    @DeleteMapping("/{id}/roles/{role}")
    @Operation(summary = "Remove a role by disabling the user (single-role model)")
    public UserDto revokeRole(@PathVariable UUID id, @PathVariable HsmRole role,
                              @AuthenticationPrincipal HsmPrincipal caller) {
        return userService.disableUser(id, caller);
    }
}
