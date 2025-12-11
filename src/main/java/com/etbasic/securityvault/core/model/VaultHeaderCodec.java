package com.etbasic.securityvault.core.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class VaultHeaderCodec {

    private static final ObjectMapper mapper = new ObjectMapper()
            .disable(SerializationFeature.INDENT_OUTPUT) // prettyPrint = false
            .enable(SerializationFeature.WRITE_NULL_MAP_VALUES) // encodeDefaults = true
            ;

    public static byte[] toJsonBytes(VaultHeader header) {
        try {
            return mapper.writeValueAsString(header).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static VaultHeader fromJsonBytes(byte[] bytes) {
        try {
            return mapper.readValue(bytes, VaultHeader.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] aadOf(VaultHeader header) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(toJsonBytes(header));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
