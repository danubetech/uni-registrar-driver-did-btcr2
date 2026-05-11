package uniregistrar.driver.did.btcr2.job;


import com.fasterxml.jackson.databind.json.JsonMapper;

import java.util.Map;

public class CreateJob {

    private static final JsonMapper jsonMapper = JsonMapper.builder().build();

    public static CreateJob fromMap(Map<String, Object> map) {
        return jsonMapper.convertValue(map, CreateJob.class);
    }

    public Map<String, Object> toMap() {
        return jsonMapper.convertValue(this, Map.class);
    }
}
