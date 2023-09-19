package com.github.mrbrunelli.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Config {
    public static Properties getProps() {
        Properties props = new Properties();

        try {
            ClassLoader cl = Config.class.getClassLoader();
            InputStream input = cl.getResourceAsStream("config.properties");

            props.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return props;
    }
}
