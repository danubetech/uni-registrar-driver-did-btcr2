package uniregistrar.driver.did.btcr2.data;

import com.fasterxml.jackson.databind.json.JsonMapper;

import java.math.BigInteger;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * An SMT Proof as described in the did:btcr2 specification.
 *
 * <p>Corresponds to the JSON proof object in the spec:
 * <pre>
 * {
 *   "id":        "&lt;&lt; Hexadecimal of Root Hash &gt;&gt;",
 *   "nonce":     "&lt;&lt; Hexadecimal of Nonce 1101 &gt;&gt;",
 *   "updateId":  "&lt;&lt; Hexadecimal of hash(Data Block 1101) &gt;&gt;",
 *   "collapsed": "&lt;&lt; Hexadecimal of collapse bitmap &gt;&gt;",
 *   "hashes":    [ "&lt;&lt; sibling hashes in traversal order &gt;&gt;" ]
 * }
 * </pre>
 *
 * <p>The {@code collapsed} bitmap encodes, for each level from the leaf (bit 0) to the root,
 * whether that level was collapsed (single-child) or not.  A set bit means the candidate hash
 * passed through unchanged; a clear bit means a sibling hash was consumed.
 */
public record SmtProof(
        byte[] id,
        BigInteger nonce,
        byte[] updateId,
        BigInteger collapsed,
        List<byte[]> hashes
) {

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .build();

    public SmtProof {
        hashes = Collections.unmodifiableList(hashes);
    }

    public Map<String, Object> toMap() {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return jsonMapper.convertValue(Map.of(
                "id", this.id() == null ? "" : encoder.encode(this.id()),
                "nonce", this.nonce() == null ? "" : encoder.encode(this.nonce().toByteArray()),
                "updateId", this.updateId() == null ? "" : encoder.encode(this.updateId()),
                "collapsed", this.collapsed() == null ? "" : encoder.encode(this.collapsed().toByteArray()),
                "hashes", this.hashes() == null ? "" : hashes.stream().map(encoder::encodeToString).toList()
        ), Map.class);
    }

    /**
     * Serialize to a human-readable JSON-like string for debugging / display.
     */
    public String toDisplayString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"id\": \"").append(SparseMerkleTree.toHex(id)).append("\",\n");
        sb.append("  \"nonce\": \"").append(nonce.toString(16)).append("\",\n");
        sb.append("  \"updateId\": \"").append(
                updateId != null ? SparseMerkleTree.toHex(updateId) : "null").append("\",\n");
        sb.append("  \"collapsed\": \"").append(collapsed.toString(16)).append("\",\n");
        sb.append("  \"hashes\": [\n");
        for (int i = 0; i < hashes.size(); i++) {
            sb.append("    \"").append(SparseMerkleTree.toHex(hashes.get(i))).append("\"");
            if (i < hashes.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ]\n}");
        return sb.toString();
    }
}