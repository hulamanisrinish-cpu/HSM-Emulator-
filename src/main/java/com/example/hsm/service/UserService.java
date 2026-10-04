package com.example.hsm.service;

import com.example.hsm.dto.CreateUserRequest;
import com.example.hsm.dto.CreateUserResponse;
import com.example.hsm.dto.UserDto;
import com.example.hsm.entity.AuditAction;
import com.example.hsm.entity.AuditOutcome;
import com.example.hsm.entity.HsmUser;
import com.example.hsm.exception.KeyNotFoundException;
import com.example.hsm.exception.UserAlreadyExistsException;
import com.example.hsm.repository.HsmUserRepository;
import com.example.hsm.security.HsmPrincipal;
import com.example.hsm.service.audit.AuditService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Manages HSM users, token issuance, and role assignments. Requires ADMIN role for all mutations.
 *
 * <p>Plain tokens are returned once at creation time and never stored.
 */
@Service
@Transactional
public class UserService {

    private final HsmUserRepository userRepo;
    private final TokenService tokenService;
    private final AuditService auditService;

    public UserService(HsmUserRepository userRepo, TokenService tokenService, AuditService auditService) {
        this.userRepo = userRepo;
        this.tokenService = tokenService;
        this.auditService = auditService;
    }

    /**
     * Creates a new user and issues a one-time bearer token. Requires ADMIN role.
     * The plain token is returned in the response and must be noted immediately.
     *
     * @param req    user creation parameters
     * @param caller the authenticated admin
     * @return response including the plain token (shown once)
     */
    @PreAuthorize("hasRole('ADMIN')")
    public CreateUserResponse createUser(CreateUserRequest req, HsmPrincipal caller) {
        if (userRepo.findByUsername(req.username()).isPresent()) {
            throw new UserAlreadyExistsException(req.username());
        }
        String plainToken = tokenService.generateToken();
        String hash = tokenService.hashToken(plainToken);
        String prefix = tokenService.extractPrefix(plainToken);
        HsmUser user = new HsmUser(req.username(), hash, prefix, req.role());
        user = userRepo.save(user);
        auditService.appendRecord(AuditAction.USER_CREATE, null, AuditOutcome.SUCCESS, caller);
        return new CreateUserResponse(user.getId(), user.getUsername(), user.getRole(),
                plainToken, "Store this token securely — it will not be shown again.");
    }

    /**
     * Lists all users. Requires ADMIN role. Never includes tokens.
     *
     * @param caller the authenticated admin
     * @return list of user metadata
     */
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserDto> listUsers(HsmPrincipal caller) {
        return userRepo.findAll().stream()
                .map(u -> new UserDto(u.getId(), u.getUsername(), u.getRole(),
                        u.getCreatedAt(), u.isEnabled()))
                .toList();
    }

    /**
     * Assigns a new role to a user. Requires ADMIN role.
     *
     * @param userId  the user's UUID
     * @param newRole the new role to assign
     * @param caller  the authenticated admin
     */
    @PreAuthorize("hasRole('ADMIN')")
    public UserDto assignRole(UUID userId, com.example.hsm.entity.HsmRole newRole, HsmPrincipal caller) {
        HsmUser user = userRepo.findById(userId)
                .orElseThrow(() -> new KeyNotFoundException(userId));
        user.setRole(newRole);
        auditService.appendRecord(AuditAction.ROLE_ASSIGN, null, AuditOutcome.SUCCESS, caller);
        return toDto(user);
    }

    /**
     * Disables a user (revokes their ability to authenticate). Requires ADMIN role.
     *
     * @param userId the user's UUID
     * @param caller the authenticated admin
     */
    @PreAuthorize("hasRole('ADMIN')")
    public UserDto disableUser(UUID userId, HsmPrincipal caller) {
        HsmUser user = userRepo.findById(userId)
                .orElseThrow(() -> new KeyNotFoundException(userId));
        user.setEnabled(false);
        auditService.appendRecord(AuditAction.USER_DISABLE, null, AuditOutcome.SUCCESS, caller);
        return toDto(user);
    }

    private UserDto toDto(HsmUser u) {
        return new UserDto(u.getId(), u.getUsername(), u.getRole(), u.getCreatedAt(), u.isEnabled());
    }
}
