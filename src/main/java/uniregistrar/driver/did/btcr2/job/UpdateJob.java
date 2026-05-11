package uniregistrar.driver.did.btcr2.job;


import com.fasterxml.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;

public record UpdateJob(String update, String updateSignPayload, String unsignedBeaconSignal, List<String> utxoSingletonSignPayloads, List<String> utxoAggregateSignPayloads, String aggregationCohortId) {

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .build();

    public static UpdateJob fromMap(Map<String, Object> map) {
        return jsonMapper.convertValue(map, UpdateJob.class);
    }

    public Map<String, Object> toMap() {
        return jsonMapper.convertValue(this, Map.class);
    }
}
