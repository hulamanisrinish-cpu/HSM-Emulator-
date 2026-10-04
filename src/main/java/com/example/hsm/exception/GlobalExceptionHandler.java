package com.example.hsm.exception;

import com.example.hsm.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

/** Maps HSM exceptions to structured HTTP responses. Never includes stack traces. */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuth(AuthenticationException ex, HttpServletRequest req) {
        return build(HttpStatus.UNAUTHORIZED, "Unauthorized", "Authentication required", req.getRequestURI());
    }

    @ExceptionHandler({AccessDeniedException.class, org.springframework.security.access.AccessDeniedException.class})
    public ResponseEntity<ErrorResponse> handleAccessDenied(RuntimeException ex, HttpServletRequest req) {
        return build(HttpStatus.FORBIDDEN, "Forbidden", "Access denied", req.getRequestURI());
    }

    @ExceptionHandler(KeyNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(KeyNotFoundException ex, HttpServletRequest req) {
        return build(HttpStatus.NOT_FOUND, "Not Found", ex.getMessage(), req.getRequestURI());
    }

    @ExceptionHandler({KeyAlreadyExistsException.class, UserAlreadyExistsException.class})
    public ResponseEntity<ErrorResponse> handleConflict(HsmException ex, HttpServletRequest req) {
        return build(HttpStatus.CONFLICT, "Conflict", ex.getMessage(), req.getRequestURI());
    }

    @ExceptionHandler(DestroyedKeyException.class)
    public ResponseEntity<ErrorResponse> handleDestroyed(DestroyedKeyException ex, HttpServletRequest req) {
        return build(HttpStatus.GONE, "Gone", ex.getMessage(), req.getRequestURI());
    }

    @ExceptionHandler(InvalidKeyStateException.class)
    public ResponseEntity<ErrorResponse> handleInvalidState(InvalidKeyStateException ex, HttpServletRequest req) {
        return build(HttpStatus.UNPROCESSABLE_ENTITY, "Unprocessable Entity", ex.getMessage(), req.getRequestURI());
    }

    @ExceptionHandler(CryptographicOperationException.class)
    public ResponseEntity<ErrorResponse> handleCryptoError(CryptographicOperationException ex, HttpServletRequest req) {
        return build(HttpStatus.BAD_REQUEST, "Bad Request", "Cryptographic operation failed", req.getRequestURI());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest req) {
        String msg = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .findFirst().orElse("Validation failed");
        return build(HttpStatus.BAD_REQUEST, "Bad Request", msg, req.getRequestURI());
    }

    @ExceptionHandler(HsmInternalException.class)
    public ResponseEntity<ErrorResponse> handleInternal(HsmInternalException ex, HttpServletRequest req) {
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error",
                "An internal error occurred", req.getRequestURI());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAll(Exception ex, HttpServletRequest req) {
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error",
                "An unexpected error occurred", req.getRequestURI());
    }

    private ResponseEntity<ErrorResponse> build(HttpStatus status, String error,
                                                 String message, String path) {
        return ResponseEntity.status(status)
                .body(new ErrorResponse(Instant.now(), status.value(), error, message, path));
    }
}
