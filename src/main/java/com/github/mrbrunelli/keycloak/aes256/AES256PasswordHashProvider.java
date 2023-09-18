package com.github.mrbrunelli.keycloak.aes256;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AES256PasswordHashProvider implements PasswordHashProvider {
    private static final String SECRET_KEY = "771a1cf03e8c7934";
    private static final String SALT = "ecf35be993624dc5";

    private final int defaultIterations;
    private final String providerId;

    public AES256PasswordHashProvider(final String providerId, final int defaultIterations) {
        this.providerId = providerId;
        this.defaultIterations = defaultIterations;
    }

    @Override
    public boolean policyCheck(PasswordPolicy passwordPolicy, PasswordCredentialModel passwordCredentialModel) {
        final int policyHashIterations = passwordPolicy.getHashIterations() == -1 ? defaultIterations : passwordPolicy.getHashIterations();

        return passwordCredentialModel.getPasswordCredentialData().getHashIterations() == policyHashIterations
                && providerId.equals(passwordCredentialModel.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        final String encodedPassword = encode(rawPassword, iterations);
        return PasswordCredentialModel.createFromValues(providerId, new byte[0], iterations, encodedPassword);
    }

    public String encode(String rawPassword, int iterations) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), iterations, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(rawPassword.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println(e.toString());
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(final String rawPassword, final PasswordCredentialModel credential) {
        final String hash = encode(rawPassword, defaultIterations);
        return hash.equals(credential.getPasswordSecretData().getValue());
    }

    @Override
    public void close() {

    }
}
