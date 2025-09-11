package uniregistrar.driver.did.btcr2.crud.create;

import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.Network;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.connections.ipfs.IPFSConnection;

import java.util.Map;

public class Create {

    private static final Logger log = LoggerFactory.getLogger(Create.class);

    private DeterministicKeybasedCreation deterministicKeybasedCreation;
    private ExternalInitialDocumentCreation externalInitialDocumentCreation;

    public Create(BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) {
        this.deterministicKeybasedCreation = new DeterministicKeybasedCreation(this, bitcoinConnector, ipfsConnection);
        this.externalInitialDocumentCreation = new ExternalInitialDocumentCreation(this, bitcoinConnector, ipfsConnection);
    }

    /*
     * 4.1 Create
     */

    // See https://dcdpr.github.io/did-btcr2/#create
    public Map.Entry<DID, DIDDocument> create(byte[] pubKeyBytes, DIDDocument intermediateDocument, Integer version, Network network, /* TODO: extra, not in spec */ Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // A did:btcr2 identifier and associated DID document can either be created deterministically from a cryptographic seed,
        // or it can be created from an arbitrary genesis intermediate DID document representation.

        Map.Entry<DID, DIDDocument> didAndInitialDocument;

        if (pubKeyBytes != null && intermediateDocument == null) {
            didAndInitialDocument = this.getDeterministicKeybasedCreation().deterministicKeybasedCreation(pubKeyBytes, version, network, didDocumentMetadata);
        } else if (intermediateDocument != null) {
            didAndInitialDocument = this.getExternalInitialDocumentCreation().externalInitialDocumentCreation(intermediateDocument, version, network, didDocumentMetadata);
        } else {
            throw new IllegalArgumentException("Incompatible 'pubKeyBytes' and 'intermediateDocument' state.");
        }

        // DID DOCUMENT METADATA

        didDocumentMetadata.put("pubKeyBytes", pubKeyBytes == null ? null : Hex.encodeHexString(pubKeyBytes));
        didDocumentMetadata.put("intermediateDocument", intermediateDocument == null ? null : intermediateDocument.toMap());

        // Return DID and initial DID document.

        if (log.isDebugEnabled()) log.debug("Create: " + didAndInitialDocument);
        return didAndInitialDocument;
    }

    /*
     * Getters and settes
     */

    public DeterministicKeybasedCreation getDeterministicKeybasedCreation() {
        return this.deterministicKeybasedCreation;
    }

    public void setDeterministicKeybasedCreation(DeterministicKeybasedCreation deterministicKeybasedCreation) {
        this.deterministicKeybasedCreation = deterministicKeybasedCreation;
    }

    public ExternalInitialDocumentCreation getExternalInitialDocumentCreation() {
        return this.externalInitialDocumentCreation;
    }

    public void setExternalInitialDocumentCreation(ExternalInitialDocumentCreation externalInitialDocumentCreation) {
        this.externalInitialDocumentCreation = externalInitialDocumentCreation;
    }
}
