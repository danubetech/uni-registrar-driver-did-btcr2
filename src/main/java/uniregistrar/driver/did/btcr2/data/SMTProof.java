package uniregistrar.driver.did.btcr2.data;

import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.util.*;

public record SMTProof(
        byte[] id,
        BigInteger nonce,
        byte[] updateId,
        BigInteger collapsed,
        List<byte[]> hashes
) {

    public SMTProof {
        hashes = Collections.unmodifiableList(hashes);
    }

    public Map<String, Object> toBtcr2Map() {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", this.id() == null ? null : encoder.encodeToString(this.id()));
        map.put("nonce", this.nonce() == null ? null : encoder.encodeToString(this.nonce().toByteArray()));
        map.put("updateId", this.updateId() == null ? null : encoder.encodeToString(this.updateId()));
        map.put("collapsed", this.collapsed() == null ? null : encoder.encodeToString(this.collapsed().toByteArray()));
        map.put("hashes", this.hashes() == null ? null : this.hashes().stream().map(encoder::encodeToString).toList());
        return map;
    }

    @Override
    public String toString() {
        return "SmtProof{" +
                "id=" + (id == null ? null : Hex.encodeHexString(id)) +
                ", nonce=" + (nonce == null ? null : Hex.encodeHexString(nonce.toByteArray())) +
                ", updateId=" + (updateId == null ? null : Hex.encodeHexString(updateId)) +
                ", collapsed=" + (collapsed == null ? null : Hex.encodeHexString(collapsed.toByteArray())) +
                ", hashes=" + (hashes == null ? null : hashes.stream().map(Hex::encodeHexString).toList()) +
                '}';
    }
}