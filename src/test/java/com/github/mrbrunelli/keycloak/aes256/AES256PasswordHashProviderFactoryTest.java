package com.github.mrbrunelli.keycloak.aes256;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;

public class AES256PasswordHashProviderFactoryTest {
    @Mock
    private KeycloakSession keycloakSession;
    private AES256PasswordHashProviderFactory factory;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);

        factory =  new AES256PasswordHashProviderFactory();
    }

    @Test
    @DisplayName("Should create an instance of provider")
    void shouldCreateAnInstanceOfProvider() {
        PasswordHashProvider provider = factory.create(keycloakSession);
        assertNotNull(provider);
    }

    @Test
    @DisplayName("Should hash a password")
    void shouldHashAPassword() {
        PasswordHashProvider provider = factory.create(keycloakSession);
        String hash = provider.encode("jabuticaba", 10);

        assertEquals("1UbfdhKtxR4riHTneekn7w==", hash);
    }

    @Test
    @DisplayName("Should verify passwords are equal")
    void shouldVerifyPasswordsAreEqual() {
        PasswordHashProvider provider = factory.create(keycloakSession);
        String hash = provider.encode("jabuticaba", 10);

        PasswordCredentialModel model = PasswordCredentialModel.createFromValues("AES", new byte[0], 10, hash);

        assertTrue(provider.verify("jabuticaba", model));
    }
}
