package uniregistrar.driver.did.btcr2.data;

import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.Reader;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SMTProof extends LinkedHashMap<String, Object> {

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .build();

    private static final Base64.Encoder base64UrlEncoder = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder base64UrlDecoder = Base64.getUrlDecoder();

    public SMTProof() {
        super();
    }

    public SMTProof(Map<? extends String, ? extends String> m) {
        super(m);
    }

    public SMTProof(byte[] id, byte[] nonce, byte[] updateId, byte[] collapsed, List<byte[]> hashes) {
        if (id != null) this.put("id", base64UrlEncoder.encodeToString(id));
        if (nonce != null) this.put("nonce", base64UrlEncoder.encodeToString(nonce));
        if (updateId != null) this.put("updateId", base64UrlEncoder.encodeToString(updateId));
        if (collapsed != null) this.put("collapsed", base64UrlEncoder.encodeToString(collapsed));
        if (hashes != null) this.put("hashes", hashes.stream().map(base64UrlEncoder::encodeToString).toList());
    }

    public static SMTProof fromJson(Reader reader) throws IOException {
        return jsonMapper.readValue(reader, SMTProof.class);
    }

    public Map<String, Object> toMap() {
        return this;
    }

    public byte[] getId() {
        return this.containsKey("id") ? base64UrlDecoder.decode((String) this.get("id")) : null;
    }

    public byte[] getNonce() {
        return this.containsKey("nonce") ? base64UrlDecoder.decode((String) this.get("nonce")) : null;
    }

    public byte[] getUpdateId() {
        return this.containsKey("updateId") ? base64UrlDecoder.decode((String) this.get("updateId")) : null;
    }

    public byte[] getCollapsed() {
        return this.containsKey("collapsed") ? base64UrlDecoder.decode((String) this.get("collapsed")) : null;
    }

    public List<byte[]> getHashes() {
        return this.containsKey("hashes") ? ((List<String>) this.get("hashes")).stream().map(base64UrlDecoder::decode).toList() : null;
    }
}