package uniregistrar.driver.did.btcr2.appendix;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.jsonld.JsonLDObject;
import org.apache.commons.codec.binary.Hex;
import org.erdtman.jcs.JsonCanonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.driver.did.btcr2.util.SHA256Util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class JsonCanonicalizationAndHash {

    private static final Logger log = LoggerFactory.getLogger(JsonCanonicalizationAndHash.class);

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static byte[] jsonCanonicalizationAndHash(String json) {
        String encodedString;
        try {
            encodedString = new JsonCanonicalizer(json).getEncodedString();
        } catch (IOException ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
        byte[] hash = SHA256Util.sha256(encodedString.getBytes(StandardCharsets.UTF_8));
        if (log.isDebugEnabled()) log.debug("jsonCanonicalizationAndHash for " + json + ": " + Hex.encodeHexString(hash));
        return hash;
    }

    public static byte[] jsonCanonicalizationAndHash(Record record) {
        String json;
        try {
            json = objectMapper.writeValueAsString(record);
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
        return jsonCanonicalizationAndHash(json);
    }

    public static byte[] jsonCanonicalizationAndHash(Map<String, Object> map) {
        String json;
        try {
            json = objectMapper.writeValueAsString(map);
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
        return jsonCanonicalizationAndHash(json);
    }

    public static byte[] jsonCanonicalizationAndHash(JsonLDObject jsonLDObject) {
        Map<String, Object> map = jsonLDObject.toMap();
        return jsonCanonicalizationAndHash(map);
    }
}
