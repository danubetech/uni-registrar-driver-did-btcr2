package uniregistrar.driver.did.btcr2.data.jsonld;

import com.fasterxml.jackson.annotation.JsonCreator;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;

import java.io.Reader;
import java.util.List;
import java.util.Map;

public class BTCR2Update extends JsonLDObject {

    @JsonCreator
    public BTCR2Update() {
        super();
    }

    protected BTCR2Update(Map<String, Object> jsonObject) {
        super(jsonObject);
    }

    /*
     * Factory methods
     */

    public static BTCR2Update fromJsonObject(Map<String, Object> jsonObject) {
        return new BTCR2Update(jsonObject);
    }

    public static BTCR2Update fromJsonLDObject(JsonLDObject jsonLDObject) { return fromJsonObject(jsonLDObject.getJsonObject()); }

    public static BTCR2Update fromJson(Reader reader) {
        return new BTCR2Update(readJson(reader));
    }

    public static BTCR2Update fromJson(String json) {
        return new BTCR2Update(readJson(json));
    }

    public static BTCR2Update fromMap(Map<String, Object> map) {
        return new BTCR2Update(map);
    }

    /*
     * Getters
     */

    public Integer getTargetVersionId() {
        Object jsonValue = JsonLDUtils.jsonLdGetJsonValue(this.getJsonObject(), "targetVersionId");
        return (Integer) jsonValue;
    }

    public String getSourceHash() {
        String jsonString = JsonLDUtils.jsonLdGetString(this.getJsonObject(), "sourceHash");
        return jsonString;
    }

    public String getTargetHash() {
        String jsonString = JsonLDUtils.jsonLdGetString(this.getJsonObject(), "targetHash");
        return jsonString;
    }

    public List<Map<String, Object>> getPatch() {
        Object jsonValue = JsonLDUtils.jsonLdGetJsonValue(this.getJsonObject(), "patch");
        return (List<Map<String, Object>>) jsonValue;
    }
}
