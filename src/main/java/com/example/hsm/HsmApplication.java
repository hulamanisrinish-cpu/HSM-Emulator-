package com.example.hsm;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the HSM Emulator application.
 *
 * <p>This is an <em>educational</em> software emulator of a Hardware Security Module.
 * It is NOT a certified HSM, does NOT provide tamper-resistant hardware protection,
 * and MUST NOT be used in production security contexts.
 */
@SpringBootApplication
public class HsmApplication {

    public static void main(String[] args) {
        SpringApplication.run(HsmApplication.class, args);
    }
}
