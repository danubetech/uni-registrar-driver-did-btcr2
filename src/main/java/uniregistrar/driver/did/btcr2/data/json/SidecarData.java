package uniregistrar.driver.did.btcr2.data.json;

import com.fasterxml.jackson.annotation.JsonProperty;
import foundation.identity.did.DIDDocument;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;

import java.util.List;
import java.util.Objects;

public class SidecarData {

    @JsonProperty("@context")
    private String context;
    private DIDDocument genesisDocument;
    private List<BTCR2Update> updates;
    private List<CASAnnouncement> casUpdates;
    private List<SMTProof> smtProofs;

    public SidecarData() {
    }

    public String getContext() {
        return context;
    }

    public void setContext(String context) {
        this.context = context;
    }

    public DIDDocument getGenesisDocument() {
        return genesisDocument;
    }

    public void setGenesisDocument(DIDDocument genesisDocument) {
        this.genesisDocument = genesisDocument;
    }

    public List<BTCR2Update> getUpdates() {
        return updates;
    }

    public void setUpdates(List<BTCR2Update> updates) {
        this.updates = updates;
    }

    public List<CASAnnouncement> getCasUpdates() {
        return casUpdates;
    }

    public void setCasUpdates(List<CASAnnouncement> casUpdates) {
        this.casUpdates = casUpdates;
    }

    public List<SMTProof> getSmtProofs() {
        return smtProofs;
    }

    public void setSmtProofs(List<SMTProof> smtProofs) {
        this.smtProofs = smtProofs;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        SidecarData that = (SidecarData) o;
        return Objects.equals(context, that.context) && Objects.equals(genesisDocument, that.genesisDocument) && Objects.equals(updates, that.updates) && Objects.equals(casUpdates, that.casUpdates) && Objects.equals(smtProofs, that.smtProofs);
    }

    @Override
    public int hashCode() {
        return Objects.hash(context, genesisDocument, updates, casUpdates, smtProofs);
    }

    @Override
    public String toString() {
        return "SidecarData{" +
                "context='" + context + '\'' +
                ", genesisDocument=" + genesisDocument +
                ", updates=" + updates +
                ", casUpdates=" + casUpdates +
                ", smtProofs=" + smtProofs +
                '}';
    }
}
