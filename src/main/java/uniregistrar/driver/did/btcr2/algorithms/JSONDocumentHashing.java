package uniregistrar.driver.did.btcr2.algorithms;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.jsonld.JsonLDObject;
import org.apache.commons.codec.binary.Hex;
import org.erdtman.jcs.JsonCanonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniresolver.driver.did.btcr2.util.SHA256Util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/*
 * JSON Document Hashing
 * See https://dcdpr.github.io/did-btcr2/algorithms.html#json-document-hashing
 */
public class JSONDocumentHashing {

    private static final Logger log = LoggerFactory.getLogger(JSONDocumentHashing.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder().build();

    public static byte[] jsonDocumentHashing(String json) {
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

    public static byte[] jsonDocumentHashing(Record record) {
        String json;
        try {
            json = jsonMapper.writeValueAsString(record);
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
        return jsonDocumentHashing(json);
    }

    public static byte[] jsonDocumentHashing(Map<String, ?> map) {
        String json;
        try {
            json = jsonMapper.writeValueAsString(map);
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
        return jsonDocumentHashing(json);
    }

    public static byte[] jsonDocumentHashing(JsonLDObject jsonLDObject) {
        Map<String, Object> map = jsonLDObject.toMap();
        return jsonDocumentHashing(map);
    }
}
