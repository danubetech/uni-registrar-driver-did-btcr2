package uniregistrar.driver.did.btcr2.crud.update;

import com.danubetech.dataintegrity.signer.DataIntegrityProofLdSigner;
import foundation.identity.did.DID;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.appendix.DeriveRootCapabilityFromDidBtcr2Identifier;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.connections.ipfs.IPFSConnection;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;

public class InvokeBTCR2Update {

    private static final Logger log = LoggerFactory.getLogger(InvokeBTCR2Update.class);

    private Update update;
    private BitcoinConnector bitcoinConnector;
    private IPFSConnection ipfsConnection;

    public InvokeBTCR2Update(Update update, BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) {
        this.update = update;
        this.bitcoinConnector = bitcoinConnector;
        this.ipfsConnection = ipfsConnection;
    }

    /*
     * 7.3.2 Invoke BTCR2 Update
     */

    // See https://dcdpr.github.io/did-btcr2/#invoke-btcr2-update
    public JsonLDObject invokeBTCR2Update(DID identifier, JsonLDObject unsecuredBtcr2Update, VerificationMethod verificationMethod, /* TODO: extra, not in spec */ Map<String, Object> didDocumentMetadata) throws RegistrationException {
        if (log.isDebugEnabled()) log.debug("invokeBTCR2Update ({}, {}, {})", identifier, unsecuredBtcr2Update, verificationMethod);

        // Set privateKeyBytes to the result of retrieving the private key bytes
        // associated with the verificationMethod value. How this is achieved is left to the implementation.

        byte[] privateKeyBytes = null; /* TODO */

        // Set rootCapability to the result of passing btcr2Identifier into the Derive Root Capability from did:btcr2 Identifier algorithm.

        JsonLDObject rootCapability = DeriveRootCapabilityFromDidBtcr2Identifier.deriveRootCapabilityFromDidBtcr2Identifier(identifier);

        // Initialize proofOptions to an empty object.
        // Set proofOptions.type to DataIntegrityProof.
        // Set proofOptions.cryptosuite to bip340-jcs-2025.
        // Set proofOptions.verificationMethod to verificationMethod.id.
        // Set proofOptions.proofPurpose to capabilityInvocation.
        // Set proofOptions.capability to rootCapability.id.
        // Set proofOptions.capabilityAction to Write.
        // Set cryptosuite to the result of executing the Cryptosuite Instantiation algorithm from the BIP340 Data Integrity specification passing in proofOptions.

        DataIntegrityProofLdSigner cryptosuite = new DataIntegrityProofLdSigner(null /* TODO */);
        cryptosuite.setCryptosuite("bip340-jcs-2025");
        cryptosuite.setVerificationMethod(verificationMethod.getId());
        cryptosuite.setProofPurpose("capabilityInvocation");
        cryptosuite.setCapability(rootCapability.getId());
        cryptosuite.setCapabilityAction("Write");

        // Set btcr2Update to the result of executing the Add Proof algorithm from VC Data Integrity passing
        // unsecuredBtcr2Update as the input document, cryptosuite, and the set of proofOptions.

        JsonLDObject btcr2Update;

        try {
            cryptosuite.sign(unsecuredBtcr2Update, true, false);
            btcr2Update = unsecuredBtcr2Update;
        } catch (IOException | GeneralSecurityException | JsonLDException ex) {
            throw new RegistrationException("Cannot sign the BTCR2 Update: " + ex.getMessage(), ex);
        }

        // Return btcr2Update.

        if (log.isDebugEnabled()) log.debug("invokeBTCR2Update: " + btcr2Update);
        return btcr2Update;
    }

    /*
     * Getters and setters
     */

    public Update getUpdate() {
        return this.update;
    }

    public void setUpdate(Update update) {
        this.update = update;
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
