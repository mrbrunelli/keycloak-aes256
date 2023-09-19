package com.github.mrbrunelli.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Config {
    public static Properties getProps() {
        try (InputStream input = Config.class.getClassLoader().getResourceAsStream("config.properties")) {
            Properties props = new Properties();
            props.load(input);
            return props;
        } catch (IOException e) {
            throw new RuntimeException("Failed to load properties file", e);
        }
    }
}
