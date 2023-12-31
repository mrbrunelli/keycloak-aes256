package com.github.mrbrunelli.keycloak.aes256;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.util.Properties;

public class AES256PasswordHashProviderFactory implements PasswordHashProviderFactory {
    public static final String ID = "AES";
    public static final int DEFAULT_ITERATIONS = 10;

    @Override
    public PasswordHashProvider create(KeycloakSession keycloakSession) {
        Properties props = com.github.mrbrunelli.config.Config.getProps();

        return new AES256PasswordHashProvider(
                ID,
                DEFAULT_ITERATIONS,
                props.getProperty("encryption.key"),
                props.getProperty("encryption.iv")
        );
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ID;
    }
}
