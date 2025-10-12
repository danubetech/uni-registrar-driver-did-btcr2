package uniregistrar.driver.did.btcr2.crud.create;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.Network;
import uniregistrar.driver.did.btcr2.appendix.JsonCanonicalizationAndHash;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.connections.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierEncoding;
import uniregistrar.driver.did.btcr2.util.JsonLDUtil;

import java.util.Map;

public class ExternalInitialDocumentCreation {

    private static final Logger log = LoggerFactory.getLogger(ExternalInitialDocumentCreation.class);

    private Create create;
    private BitcoinConnector bitcoinConnector;
    private IPFSConnection ipfsConnection;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public ExternalInitialDocumentCreation(Create create, BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) {
        this.create = create;
        this.bitcoinConnector = bitcoinConnector;
        this.ipfsConnection = ipfsConnection;
    }

    /*
     * 4.1.2 External Initial Document Creation
     */

    // https://dcdpr.github.io/did-btcr2/#external-initial-document-creation
    public Map.Entry<DID, DIDDocument> externalInitialDocumentCreation(DIDDocument intermediateDocument, Integer version, Network network, /* TODO: extra, not in spec */ Map<String, Object> didDocumentMetadata) throws RegistrationException {
        if (log.isDebugEnabled()) log.debug("externalInitialDocumentCreation ({}, {}, {})", intermediateDocument, version, network);

        // Set idType to “external”.

        String idType = "external";

        // Set version to 1.

        if (version == null) version = 1;

        // Set network to the desired network.

        network = network;

        // Set genesisBytes to the result of passing intermediateDocument into the JSON Canonicalization and Hash algorithm.

        byte[] genesisBytes = JsonCanonicalizationAndHash.jsonCanonicalizationAndHash(intermediateDocument);

        // Pass idType, version, network, and genesisBytes to the did:btcr2 Identifier Encoding algorithm, retrieving id.

        DID id = DidBtcr2IdentifierEncoding.didBtcr2IdentifierEncoding(idType, version, network, genesisBytes);

        // Set did to id.

        DID did = id;

        // Set initialDocument to a copy of the intermediateDocument.

        DIDDocument initialDocument = JsonLDUtil.copy(intermediateDocument, DIDDocument.class);

        // Replace all did:btcr2:_ values in the initialDocument with the did.

        try {
            initialDocument = objectMapper.readValue(objectMapper.writeValueAsString(initialDocument).replace("did:btcr2:_", did.getDidString()), DIDDocument.class);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException(ex);
        }

        // Optionally store canonicalBytes on a Content Addressable Storage (CAS) system like IPFS. If doing so, implementations MUST use CIDs generated following the IPFS v1 algorithm.

        // TODO

        // Return did and initialDocument.

        return Map.of(did, initialDocument).entrySet().iterator().next();
    }

    /*
     * Getters and setters
     */

    public Create getRead() {
        return create;
    }

    public void setRead(Create create) {
        this.create = create;
    }

    public BitcoinConnector getBitcoinConnector() {
        return bitcoinConnector;
    }

    public void setBitcoinConnector(BitcoinConnector bitcoinConnector) {
        this.bitcoinConnector = bitcoinConnector;
    }

    public IPFSConnection getIpfsConnection() {
        return ipfsConnection;
    }

    public void setIpfsConnection(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }
}
