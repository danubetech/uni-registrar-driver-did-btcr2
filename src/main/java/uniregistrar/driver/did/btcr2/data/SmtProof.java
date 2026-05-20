package uniregistrar.driver.did.btcr2.data;

import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.util.*;

public record SmtProof(
        byte[] rootHash,
        BigInteger index,
        byte[] leafHash,
        BigInteger collapsed,
        List<byte[]> hashes
) {

    public SmtProof {
        hashes = Collections.unmodifiableList(hashes);
    }

    public Map<String, Object> toBtcr2Map() {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", this.rootHash() == null ? null : encoder.encodeToString(this.rootHash()));
        map.put("nonce", this.index() == null ? null : encoder.encodeToString(this.index().toByteArray()));
        map.put("updateId", this.leafHash() == null ? null : encoder.encodeToString(this.leafHash()));
        map.put("collapsed", this.collapsed() == null ? null : encoder.encodeToString(this.collapsed().toByteArray()));
        map.put("hashes", this.hashes() == null ? null : this.hashes().stream().map(encoder::encodeToString).toList());
        return map;
    }

    @Override
    public String toString() {
        return "SmtProof{" +
                "rootHash=" + Hex.encodeHexString(rootHash) +
                ", index=" + index +
                ", leafHash=" + Hex.encodeHexString(leafHash) +
                ", collapsed=" + collapsed +
                ", hashes=" + (hashes == null ? null : hashes.stream().map(Hex::encodeHexString).toList()) +
                '}';
    }
}