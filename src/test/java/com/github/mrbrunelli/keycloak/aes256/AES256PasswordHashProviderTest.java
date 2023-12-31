package com.github.mrbrunelli.keycloak.aes256;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.models.credential.PasswordCredentialModel;

import static org.junit.jupiter.api.Assertions.*;

public class AES256PasswordHashProviderTest {
    private final int iterations = 10;
    private final String id = "AES";
    private final String encryptionKey = "LrUrPwwusH2c37d4";
    private final String encryptionIv = "pdFuHO2FYzYtgyaS";
    private final AES256PasswordHashProvider provider = new AES256PasswordHashProvider(id, iterations, encryptionKey, encryptionIv);

    @Test
    @DisplayName("Should hash the password")
    void shouldHashThePassword() {
        assertNotNull(provider.encode("jabuticaba", iterations));
    }

    @Test
    @DisplayName("Should passwords must be equal")
    void shouldPasswordsMustBeEqual() {
        String rawPassword = "jabuticaba";
        String hashedPassword = provider.encode(rawPassword, iterations);
        PasswordCredentialModel model = PasswordCredentialModel.createFromValues(id, new byte[0], iterations, hashedPassword);

        assertTrue(provider.verify(rawPassword, model));
    }

    @Test
    @DisplayName("Should passwords must be not equal")
    void shouldPasswordsMustBeNotEqual() {
        String rawPassword = "jabuticaba";
        String hashedPassword = provider.encode("melancia123laranja", iterations);
        PasswordCredentialModel model = PasswordCredentialModel.createFromValues(id, new byte[0], iterations, hashedPassword);

        assertFalse(provider.verify(rawPassword, model));
    }

    @Test
    @DisplayName("Should throw if encryption key is less than 16 characters")
    void ShouldThrowIfEncryptionKeyIsLessThan16Characters() {
        String tooShortEncryptionKey = "tooShort";
        AES256PasswordHashProvider provider = new AES256PasswordHashProvider(id, iterations, tooShortEncryptionKey, encryptionIv);

       RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            provider.encode("jabuticaba", iterations);
        });

       assertEquals("java.security.InvalidKeyException: Invalid AES key length: 8 bytes", exception.getMessage());
    }

    @Test
    @DisplayName("Should throw if encryption iv is less than 16 characters")
    void ShouldThrowIfEncryptionIvIsLessThan16Characters() {
        String tooShortEncryptionIv = "tooShort";
        AES256PasswordHashProvider provider = new AES256PasswordHashProvider(id, iterations, encryptionKey, tooShortEncryptionIv);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            provider.encode("jabuticaba", iterations);
        });

        assertEquals("java.security.InvalidAlgorithmParameterException: Wrong IV length: must be 16 bytes long", exception.getMessage());
    }
}
