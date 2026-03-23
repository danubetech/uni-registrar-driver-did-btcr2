package uniregistrar.driver.did.btcr2.crud.create;

import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.Network;
import uniregistrar.driver.did.btcr2.appendix.JsonCanonicalizationAndHash;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.connections.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.data.records.GenesisBytesType;
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierEncoding;

import java.util.AbstractMap;
import java.util.Map;

public class Create {

    private static final Logger log = LoggerFactory.getLogger(Create.class);

    private BitcoinConnector bitcoinConnector;
    private IPFSConnection ipfsConnection;

    public Create(BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) {
        this.bitcoinConnector = bitcoinConnector;
        this.ipfsConnection = ipfsConnection;
    }

    /*
     * Create
     * See https://dcdpr.github.io/did-btcr2/operations/create.html#create
     */

    public Map.Entry<DID, DIDDocument> create(byte[] initialKey, DIDDocument genesisDocument, Integer version, Network network, /* TODO: extra, not in spec */ Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // A did:btcr2 identifier encodes a few pieces of information: an indicator for a specific Bitcoin network and a collection of Genesis Bytes.

        byte[] genesisBytes;
        GenesisBytesType genesisBytesType;

        if (initialKey != null && genesisDocument == null) {
            genesisBytes = this.secp256k1PublicKey(initialKey);
            genesisBytesType = GenesisBytesType.SECP256K1PUBLICKEY;
        } else if (genesisDocument != null) {
            genesisBytes = this.genesisDocumentHash(genesisDocument);
            genesisBytesType = GenesisBytesType.SHA256HASH;
        } else {
            throw new IllegalArgumentException("Incompatible 'initialKey' and 'genesisDocument' state.");
        }

        // A specification version number is also included.

        if (version == null) version = 1;

        // These three values are encoded with the DID-BTCR2 Identifier Encoding algorithm.

        DID did = DidBtcr2IdentifierEncoding.didBtcr2IdentifierEncoding(version, network, genesisBytes, genesisBytesType);
        Map.Entry<DID, DIDDocument> didAndInitialDocument = new AbstractMap.SimpleEntry<>(did, )

        // DID DOCUMENT METADATA

        didDocumentMetadata.put("initialKey", initialKey == null ? null : Hex.encodeHexString(initialKey));
        didDocumentMetadata.put("genesisDocument", genesisDocument == null ? null : genesisDocument.toMap());

        // Return DID and initial DID document.

        if (log.isDebugEnabled()) log.debug("Create: " + didAndInitialDocument);
        return didAndInitialDocument;
    }

    /*
     * secp256k1 Public Key
     * See https://dcdpr.github.io/did-btcr2/operations/create.html#secp256k1-public-key
     */

    public byte[] secp256k1PublicKey(byte[] initialKey) throws RegistrationException {

        // An secp256k1 public key can be used as the Genesis Bytes.

        byte[] genesisBytes = initialKey;

        // The key MUST be in its compressed SEC format: a 33-byte representation consisting
        // of a single prefix byte (0x02 or 0x03) followed by the 32-byte x-coordinate of the elliptic curve point.

        if (initialKey.length != 33) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid initial key length: " + initialKey.length);
        if (initialKey[0] != 0x02 && initialKey[1] != 0x03) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid initial key prefix byte: " + Hex.encodeHexString(initialKey));

        if (log.isDebugEnabled()) log.debug("secp256k1PublicKey: {} -> {}", Hex.encodeHexString(initialKey), Hex.encodeHexString(genesisBytes));
        return genesisBytes;
    }

    /*
     * Genesis Document Hash
     * See https://dcdpr.github.io/did-btcr2/operations/create.html#genesis-document-hash
     */

    public byte[] genesisDocumentHash(DIDDocument genesisDocument) {

        // A Genesis Document can be used as the Genesis Bytes, but MUST be hashed to 32 bytes with the JSON Document Hashing algorithm.

        byte[] genesisBytes = JsonCanonicalizationAndHash.jsonCanonicalizationAndHash(genesisDocument);

        if (log.isDebugEnabled()) log.debug("genesisDocumentHash: {} -> {}", genesisDocument, Hex.encodeHexString(genesisBytes));
    }

    /*
     * Getters and setters
     */

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
