package uniregistrar.driver.did.btcr2.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.jsonld.JsonLDObject;

public class JsonLDUtil {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static <T extends JsonLDObject> T copy(T jsonLDObject, Class<T> clazz) {
        try {
            return objectMapper.readValue(objectMapper.writeValueAsString(jsonLDObject), clazz);
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }
}
