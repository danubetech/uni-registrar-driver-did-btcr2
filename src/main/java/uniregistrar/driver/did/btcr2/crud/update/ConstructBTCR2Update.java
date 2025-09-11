package uniregistrar.driver.did.btcr2.crud.update;

import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.validation.Validation;
import foundation.identity.jsonld.JsonLDObject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonPatch;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.appendix.JsonCanonicalizationAndHash;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.connections.ipfs.IPFSConnection;

import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ConstructBTCR2Update {

    private static final Logger log = LoggerFactory.getLogger(ConstructBTCR2Update.class);

    private Update update;
    private BitcoinConnector bitcoinConnector;
    private IPFSConnection ipfsConnection;

    public ConstructBTCR2Update(Update update, BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) {
        this.update = update;
        this.bitcoinConnector = bitcoinConnector;
        this.ipfsConnection = ipfsConnection;
    }

    /*
     * 7.3.1 Construct BTCR2 Update
     */

    // See https://dcdpr.github.io/did-btcr2/#construct-btcr2-update
    public JsonLDObject constructBTCR2Update(DID identifier, DIDDocument sourceDocument, Integer sourceVersionId, JsonPatch documentPatch, /* TODO: extra, not in spec */ Map<String, Object> didDocumentMetadata) throws RegistrationException {
        if (log.isDebugEnabled()) log.debug("constructBTCR2Update ({}, {}, {}, {})", identifier, sourceDocument, sourceVersionId, documentPatch);

        // Check that sourceDocument.id equals btcr2Identifier else MUST raise invalidDidUpdate error.

        if (! sourceDocument.getId().equals(identifier.toUri())) {
            throw new RegistrationException("invalidDidUpdate", "Invalid DID Update: sourceDocument.id " + sourceDocument.getId() + " does not match identifier " + identifier);
        }

        // Initialize unsecuredBtcr2Update to an empty object.

        Map<String, Object> unsecuredBtcr2Update = new LinkedHashMap<>();

        // Set unsecuredBtcr2Update.@context to the following list. ["https://w3id.org/zcap/v1",
        // "https://w3id.org/security/data-integrity/v2", "https://w3id.org/json-ld-patch/v1", "https://btcr2.dev/context/v1"]

        unsecuredBtcr2Update.put("@context", List.of("https://w3id.org/zcap/v1", "https://w3id.org/security/data-integrity/v2", "https://w3id.org/json-ld-patch/v1", "https://btcr2.dev/context/v1"));

        // Set unsecuredBtcr2Update.patch to documentPatch.

        unsecuredBtcr2Update.put("patch", documentPatch.toJsonArray());

        // Set targetDocument to the result of applying the documentPatch to the sourceDocument, following the JSON Patch specification.

        JsonObject didDocumentObject = Json.createObjectBuilder(sourceDocument.toMap()).build();
        JsonObject patchedDidDocumentObject = documentPatch.apply(didDocumentObject);
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).write(patchedDidDocumentObject);
        DIDDocument targetDocument = DIDDocument.fromJson(stringWriter.toString());

        // Validate targetDocument is a conformant DID document, else MUST raise invalidDidUpdate error.

        try {
            Validation.validate(targetDocument);
        } catch (Exception ex) {
            throw new RegistrationException("invalidDidUpdate", "Invalid DID document: " + ex.getMessage(), ex);
        }

        // Set sourceHashBytes to the result of passing sourceDocument into the JSON Canonicalization and Hash algorithm.

        byte[] sourceHashBytes = JsonCanonicalizationAndHash.jsonCanonicalizationAndHash(sourceDocument);

        // Set unsecuredBtcr2Update.sourceHash to the base64 of sourceHashBytes.

        unsecuredBtcr2Update.put("sourceHash", Base64.encodeBase64String(sourceHashBytes));

        // Set targetHashBytes to the result of passing targetDocument into the JSON Canonicalization and Hash algorithm.

        byte[] targetHashBytes = JsonCanonicalizationAndHash.jsonCanonicalizationAndHash(targetDocument);

        // Set unsecuredBtcr2Update.targetHash to the base64 of targetHashBytes.

        unsecuredBtcr2Update.put("targetHash", Base64.encodeBase64String(targetHashBytes));

        // Set unsecuredBtcr2Update.targetVersionId to sourceVersionId + 1

        unsecuredBtcr2Update.put("targetVersionId", sourceVersionId + 1);

        // Return unsecuredBtcr2Update.

        JsonLDObject jsonldUnsecuredBtcr2Update = JsonLDObject.fromJsonObject(unsecuredBtcr2Update);
        if (log.isDebugEnabled()) log.debug("constructBTCR2Update: " + jsonldUnsecuredBtcr2Update);
        return jsonldUnsecuredBtcr2Update;
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
        return this.bitcoinConnector;
    }

    public void setBitcoinConnector(BitcoinConnector bitcoinConnector) {
        this.bitcoinConnector = bitcoinConnector;
    }

    public IPFSConnection getIpfsConnection() {
        return this.ipfsConnection;
    }

    public void setIpfsConnection(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }
}
