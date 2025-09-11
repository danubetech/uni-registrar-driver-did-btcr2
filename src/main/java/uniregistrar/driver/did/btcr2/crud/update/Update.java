package uniregistrar.driver.did.btcr2.crud.update;

import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDObject;
import jakarta.json.JsonPatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.connections.ipfs.IPFSConnection;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class Update {

    private static final Logger log = LoggerFactory.getLogger(Update.class);

    private ConstructBTCR2Update constructBTCR2Update;
    private InvokeBTCR2Update invokeBTCR2Update;
    private AnnounceDIDUpdate announceDIDUpdate;

    public Update(BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) {
        this.constructBTCR2Update = new ConstructBTCR2Update(this, bitcoinConnector, ipfsConnection);
        this.invokeBTCR2Update = new InvokeBTCR2Update(this, bitcoinConnector, ipfsConnection);
        this.announceDIDUpdate = new AnnounceDIDUpdate(this, bitcoinConnector, ipfsConnection);
    }

    /*
     * 7.3 Update
     */

    // See https://dcdpr.github.io/did-btcr2/#update
    public List<Map<String, Object>> update(DID identifier, DIDDocument sourceDocument, Integer sourceVersionId, JsonPatch documentPatch, URI verificationMethodId, List<URI> beaconIds, /* TODO: extra, not in spec */ Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // Set unsecuredUpdate to the result of passing btcr2Identifier,
        // sourceDocument, sourceVersionId, and documentPatch into the Construct BTCR2 Update algorithm.

        JsonLDObject unsecuredUpdate = this.getConstructDIDUpdatePayload().constructBTCR2Update(identifier, sourceDocument, sourceVersionId, documentPatch, didDocumentMetadata);

        // Set verificationMethod to the result of retrieving the verificationMethod from sourceDocument using
        // the verificationMethodId.

        VerificationMethod verificationMethod = sourceDocument.getVerificationMethods().stream().filter(v -> verificationMethodId.equals(v.getId())).findFirst().orElse(null);
        if (verificationMethod == null) throw new RegistrationException("invalidVerificationMethod", "Verification method not found: " + verificationMethodId);

        // Validate the verificationMethod is a BIP340 Multikey:
        // verificationMethod.type == Multikey
        // verificationMethod.publicKeyMultibase[4] == zQ3s

        if (! "MultiKey".equals(verificationMethod.getType()) || ! "zQ3s".equals(verificationMethod.getPublicKeyMultibase().substring(0, 4))) {
            throw new RegistrationException("Invalid verification method: " + verificationMethod.getType() + ", " + verificationMethod.getPublicKeyMultibase());
        }

        // Set unsecuredBtcr2Update to the result of passing btcr2Identifier, unsecuredUpdate, and
        // verificationMethod` to the Invoke BTCR2 Update algorithm.

        JsonLDObject btcr2Update = this.getInvokeDIDUpdatePayload().invokeBTCR2Update(identifier, unsecuredUpdate, verificationMethod, didDocumentMetadata);

        // Set signalsMetadata to the result of passing btcr2Identifier, sourceDocument, beaconIds and
        // unsecuredBtcr2Update to the Announce DID Update algorithm.

        List<Map<String, Object>> signalsMetadata = this.getAnnounceDIDUpdate().announceDIDUpdate(identifier, sourceDocument, beaconIds, btcr2Update, didDocumentMetadata);

        // Return signalsMetadata. It is up to implementations to ensure that the signalsMetadata is persisted.

        if (log.isDebugEnabled()) log.debug("Update: " + signalsMetadata);
        return signalsMetadata;
    }

    /*
     * Getters and settes
     */

    public ConstructBTCR2Update getConstructDIDUpdatePayload() {
        return this.constructBTCR2Update;
    }

    public void setConstructDIDUpdatePayload(ConstructBTCR2Update constructBTCR2Update) {
        this.constructBTCR2Update = constructBTCR2Update;
    }

    public InvokeBTCR2Update getInvokeDIDUpdatePayload() {
        return this.invokeBTCR2Update;
    }

    public void setInvokeDIDUpdatePayload(InvokeBTCR2Update invokeBTCR2Update) {
        this.invokeBTCR2Update = invokeBTCR2Update;
    }

    public AnnounceDIDUpdate getAnnounceDIDUpdate() {
        return this.announceDIDUpdate;
    }

    public void setAnnounceDIDUpdate(AnnounceDIDUpdate announceDIDUpdate) {
        this.announceDIDUpdate = announceDIDUpdate;
    }
}
