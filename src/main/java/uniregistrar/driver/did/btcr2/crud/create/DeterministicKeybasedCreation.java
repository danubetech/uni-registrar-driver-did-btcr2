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
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierEncoding;

import java.util.Map;

public class DeterministicKeybasedCreation {

    private static final Logger log = LoggerFactory.getLogger(DeterministicKeybasedCreation.class);

    private Create create;
    private BitcoinConnector bitcoinConnector;
    private IPFSConnection ipfsConnection;

    public DeterministicKeybasedCreation(Create create, BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) {
        this.create = create;
        this.bitcoinConnector = bitcoinConnector;
        this.ipfsConnection = ipfsConnection;
    }

    /*
     * 4.1.1 Deterministic Key-based Creation
     */

    // See https://dcdpr.github.io/did-btcr2/#deterministic-key-based-creation
    public Map.Entry<DID, DIDDocument> deterministicKeybasedCreation(byte[] pubKeyBytes, Integer version, Network network, /* TODO: extra, not in spec */ Map<String, Object> didDocumentMetadata) throws RegistrationException {
        if (log.isDebugEnabled()) log.debug("deterministicKeybasedCreation ({}, {}, {})", Hex.encodeHexString(pubKeyBytes), version, network);

        // Set idType to “key”.

        String idType = "key";

        // Set version to 1.

        if (version == null) version = 1;

        // Set network to the desired network.

        network = network;

        // Set genesisBytes to pubKeyBytes.

        byte[] genesisBytes = pubKeyBytes;

        // Pass idType, version, network, and genesisBytes to the did:btcr2 Identifier Encoding algorithm, retrieving id.

        DID id = DidBtcr2IdentifierEncoding.didBtcr2IdentifierEncoding(idType, version, network, genesisBytes);

        // Set did to id.

        DID did = id;

        // Set initialDocument to the result of passing did into the Read algorithm.

        DIDDocument initialDocument = DIDDocument.builder().id(did.toUri()).build(); /* TODO */

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
