package uniregistrar.driver.did.btcr2.data;

import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.Reader;
import java.util.LinkedHashMap;
import java.util.Map;

public class CASAnnouncement extends LinkedHashMap<String, String> {

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .build();

    public CASAnnouncement() {
        super();
    }

    public CASAnnouncement(Map<? extends String, ? extends String> m) {
        super(m);
    }

    public static CASAnnouncement fromJson(Reader reader) throws IOException {
        return jsonMapper.readValue(reader, CASAnnouncement.class);
    }

    public Map<String, String> toMap() {
        return this;
    }
}
