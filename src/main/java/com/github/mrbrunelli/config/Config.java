package com.github.mrbrunelli.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Config {
    public static Properties getProps() {
        Properties props = new Properties();

        try (InputStream input = Config.class.getClassLoader().getResourceAsStream("config.properties")) {
            props.load(input);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load properties file", e);
        }

        return props;
    }
}
