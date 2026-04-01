package uniregistrar.driver.did.btcr2.job;


import com.fasterxml.jackson.databind.json.JsonMapper;

import java.util.Map;

public class CreateJob {

    private static final JsonMapper jsonMapper = JsonMapper.builder().build();

    public CreateJob() {
    }

    public static CreateJob fromJsonObject(Map<String, Object> jsonObject) {
        return jsonMapper.convertValue(jsonObject, CreateJob.class);
    }

    public Map<String, Object> toJsonObject() {
        return jsonMapper.convertValue(this, Map.class);
    }
}
