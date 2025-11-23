package com.etbasic.securityvault.core.json;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.Base64;

/**
 * Serializer/Deserializer Jackson per byte[] con codifica Base64.
 *
 * Equivalente concettuale di:
 * object Base64ByteArraySerializer : KSerializer<ByteArray>
 * in kotlinx.serialization.
 */
public final class Base64ByteArraySerializer {

    private Base64ByteArraySerializer() {
        // utility class, no instances
    }

    /**
     * Serializza byte[] come stringa Base64.
     */
    public static class Serializer extends JsonSerializer<byte[]> {

        @Override
        public void serialize(byte[] value,
                              JsonGenerator gen,
                              SerializerProvider serializers) throws IOException {

            if (value == null) {
                gen.writeNull();
                return;
            }

            String base64 = Base64.getEncoder().encodeToString(value);
            gen.writeString(base64);
        }
    }

    /**
     * Deserializza una stringa Base64 in byte[].
     */
    public static class Deserializer extends JsonDeserializer<byte[]> {

        @Override
        public byte[] deserialize(JsonParser p,
                                  DeserializationContext ctxt) throws IOException {

            String text = p.getValueAsString();
            if (text == null) {
                return null;
            }

            return Base64.getDecoder().decode(text);
        }
    }
}
