package uniregistrar.driver.did.btcr2.data.json;

import java.util.List;
import java.util.Objects;

public class SMTProof {

    private String id;
    private String nonce;
    private String updateId;
    private String collapsed;
    private List<String> hashes;

    public SMTProof() {
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getUpdateId() {
        return updateId;
    }

    public void setUpdateId(String updateId) {
        this.updateId = updateId;
    }

    public String getCollapsed() {
        return collapsed;
    }

    public void setCollapsed(String collapsed) {
        this.collapsed = collapsed;
    }

    public List<String> getHashes() {
        return hashes;
    }

    public void setHashes(List<String> hashes) {
        this.hashes = hashes;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        SMTProof smtProof = (SMTProof) o;
        return Objects.equals(id, smtProof.id) && Objects.equals(nonce, smtProof.nonce) && Objects.equals(updateId, smtProof.updateId) && Objects.equals(collapsed, smtProof.collapsed) && Objects.equals(hashes, smtProof.hashes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, nonce, updateId, collapsed, hashes);
    }

    @Override
    public String toString() {
        return "SMTProof{" +
                "id='" + id + '\'' +
                ", nonce='" + nonce + '\'' +
                ", updateId='" + updateId + '\'' +
                ", collapsed='" + collapsed + '\'' +
                ", hashes=" + hashes +
                '}';
    }
}
