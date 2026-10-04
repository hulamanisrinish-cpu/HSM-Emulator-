package com.example.hsm.service;

import com.example.hsm.entity.HsmConfig;
import com.example.hsm.exception.CryptographicOperationException;
import com.example.hsm.exception.HsmInternalException;
import com.example.hsm.repository.HsmConfigRepository;
import com.example.hsm.service.crypto.MasterKeyService;
import com.example.hsm.service.crypto.WrappedKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class MasterKeyServiceTest {

    private HsmConfigRepository configRepo;

    @BeforeEach
    void setUp() {
        configRepo = mock(HsmConfigRepository.class);
        when(configRepo.findByConfigKey(anyString())).thenReturn(Optional.empty());
        when(configRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    @AfterEach
    void cleanup() {
        System.clearProperty("hsm.master-key.passphrase");
    }

    @Test
    void samePassphraseAndSaltProducesSameKey() {
        System.setProperty("hsm.master-key.passphrase", "test-pass-123");
        // Seed a fixed salt
        String salt64 = java.util.Base64.getEncoder().encodeToString(new byte[16]);
        when(configRepo.findByConfigKey(anyString())).thenReturn(
                Optional.of(new HsmConfig("master_key_salt", salt64)));

        MasterKeyService svc1 = buildService(310000);
        MasterKeyService svc2 = buildService(310000);

        byte[] data = "hello".getBytes();
        WrappedKey wk = svc1.wrapKey(java.util.Arrays.copyOf(data, data.length));
        byte[] unwrapped = svc2.unwrapKey(wk);
        assertArrayEquals("hello".getBytes(), unwrapped);
    }

    @Test
    void differentSaltProducesDifferentKey() {
        System.setProperty("hsm.master-key.passphrase", "same-pass");
        byte[] salt1 = new byte[16]; salt1[0] = 1;
        byte[] salt2 = new byte[16]; salt2[0] = 2;

        when(configRepo.findByConfigKey(anyString()))
                .thenReturn(Optional.of(new HsmConfig("master_key_salt",
                        java.util.Base64.getEncoder().encodeToString(salt1))))
                .thenReturn(Optional.of(new HsmConfig("master_key_salt",
                        java.util.Base64.getEncoder().encodeToString(salt2))));

        MasterKeyService svc1 = buildService(310000);
        MasterKeyService svc2 = buildService(310000);

        byte[] data = new byte[32]; // 32 byte AES key
        WrappedKey wk = svc1.wrapKey(java.util.Arrays.copyOf(data, data.length));
        // svc2 has different salt — unwrap should fail with tag mismatch
        assertThrows(CryptographicOperationException.class, () -> svc2.unwrapKey(wk));
    }

    @Test
    void missingPassphraseEnvVarFailsFast() {
        // Neither system env nor property is set
        System.clearProperty("hsm.master-key.passphrase");
        MasterKeyService svc = new MasterKeyService(configRepo);
        ReflectionTestUtils.setField(svc, "iterations", 310000);
        ReflectionTestUtils.setField(svc, "saltLength", 16);
        assertThrows(HsmInternalException.class, svc::init);
    }

    @Test
    void iterationCountBelowMinimumFailsFast() {
        System.setProperty("hsm.master-key.passphrase", "test-pass");
        MasterKeyService svc = new MasterKeyService(configRepo);
        ReflectionTestUtils.setField(svc, "iterations", 100);
        ReflectionTestUtils.setField(svc, "saltLength", 16);
        assertThrows(HsmInternalException.class, svc::init);
    }

    private MasterKeyService buildService(int iterations) {
        MasterKeyService svc = new MasterKeyService(configRepo);
        ReflectionTestUtils.setField(svc, "iterations", iterations);
        ReflectionTestUtils.setField(svc, "saltLength", 16);
        svc.init();
        return svc;
    }
}
