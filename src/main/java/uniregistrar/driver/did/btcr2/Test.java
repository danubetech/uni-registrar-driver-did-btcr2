package uniregistrar.driver.did.btcr2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.json.JsonMapper;
import jakarta.json.Json;
import jakarta.json.JsonPatch;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class Test {

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .defaultPropertyInclusion(JsonInclude.Value.ALL_NON_NULL)
            .build();

    static String PATCH = """
            {
                  "op": "add",
                  "path": "/service/0",
                  "value": {
                    "id": "did:btcr2:k1q5p5669egtkwgknupkt6t6y3jkhrhk6lwwvqdza0xg2tes3p27nljqc0d2cqk#service-1",
                    "type": "MyService",
                    "serviceEndpoint": "https://localhost:1234/"
                  }
                }
            """;
    public static void main(String[] args) throws Exception {
        List<Map<String, Object>> jsonPatchesObjects = new LinkedList<>();
        jsonPatchesObjects.add(jsonMapper.readValue(PATCH, Map.class));
        JsonPatch jsonPatches = Json.createPatch(Json.createArrayBuilder(jsonPatchesObjects).build());
        System.out.println(jsonPatches.toJsonArray());
        System.out.println(jsonPatches.toJsonArray().getFirst());
        System.out.println(jsonPatches.toJsonArray().getClass().getName());
        System.out.println(jsonPatches.toJsonArray().getFirst().getClass().getName());
        System.out.println(jsonMapper.writeValueAsString(jsonPatches.toJsonArray()));
        System.out.println(jsonMapper.writeValueAsString(jsonPatches.toJsonArray().getFirst()));
        System.out.println(jsonPatches.toJsonArray().toString());
        System.out.println(jsonPatches.toJsonArray().getFirst().toString());
    }
}
