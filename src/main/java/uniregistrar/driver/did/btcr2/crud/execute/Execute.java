package uniregistrar.driver.did.btcr2.crud.execute;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.Network;
import com.danubetech.btc.syntax.GenesisBytesType;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.appendix.JsonCanonicalizationAndHash;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierEncoding;

import java.util.Map;

/*
 * Create
 * See https://dcdpr.github.io/did-btcr2/operations/create.html#create
 */

public class Execute {

    private static final Logger log = LoggerFactory.getLogger(Execute.class);

    private IPFSConnection ipfsConnection;

    public Execute(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }

    public ExecuteInitResult create(BitcoinConnection bitcoinConnection, byte[] initialKey, DIDDocument genesisDocument, Integer version, Network network, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // A did:btcr2 identifier encodes a few pieces of information: an indicator for a specific Bitcoin network and a collection of Genesis Bytes.

        byte[] genesisBytes;
        GenesisBytesType genesisBytesType;

        if (genesisDocument == null) {
            genesisBytes = this.secp256k1PublicKey(initialKey);
            genesisBytesType = GenesisBytesType.SECP256K1PUBLICKEY;
        } else {
            genesisBytes = this.genesisDocumentHash(genesisDocument);
            genesisBytesType = GenesisBytesType.SHA256HASH;
        }

        // A specification version number is also included.

        if (version == null) version = 1;

        // These three values are encoded with the DID-BTCR2 Identifier Encoding algorithm.

        DID did = DidBtcr2IdentifierEncoding.didBtcr2IdentifierEncoding(version, network, genesisBytes, genesisBytesType);

        // result

        ExecuteInitResult executeInitResult = new ExecuteInitResult(initialKey, genesisDocument, did);
        if (log.isDebugEnabled()) log.debug("Create: " + executeInitResult);
        return executeInitResult;
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
        if (initialKey[0] != 0x02 && initialKey[0] != 0x03) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid initial key prefix byte: " + Hex.encodeHexString(initialKey));

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
        return genesisBytes;
    }

    /*
     * Getters and setters
     */

    public IPFSConnection getIpfsConnection() {
        return ipfsConnection;
    }

    public void setIpfsConnection(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }
}
