package com.github.mrbrunelli.keycloak.aes256;

import org.keycloak.models.KeycloakSession;

public class Main {
    public static void main(String[] args) {
        var provider = new AES256PasswordHashProvider("AES", 10);
        var hash = provider.encode("jabuticaba", 10);

        System.out.println(hash);
    }
}
