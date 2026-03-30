package uniregistrar.driver.did.btcr2.crud.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.records.Tx;
import com.danubetech.btc.connection.records.TxOut;
import com.danubetech.btc.util.AddressUtil;
import com.danubetech.dataintegrity.signer.DataIntegrityProofLdSigner;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.Service;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDDereferencer;
import foundation.identity.jsonld.JsonLDException;
import jakarta.json.JsonPatch;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.uri.BitcoinURIParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.algorithms.JSONDocumentHashing;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.util.JSONPatchUtil;
import uniregistrar.openapi.model.SigningResponse;
import uniregistrar.openapi.model.VerificationMethodPublicData;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

public class Update {

    private static final String BTCR2_UNSIGNED_UPDATE_TEMPLATE =
            """
                {
                  "@context": [
                    "https://w3id.org/security/v2",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/json-ld-patch/v1",
                    "https://btcr2.dev/context/v1"
                  ],
                  "patch": {{array-of-patches}},
                  "sourceHash": "{{source-hash}}",
                  "targetHash": "{{target-hash}}",
                  "targetVersionId": {{target-version-id}}
                }
            """;

    private static final String DATA_INTEGRITY_TEMPLATE =
            """
                {
                  "@context": [
                    "https://w3id.org/security/v2",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/json-ld-patch/v1",
                    "https://btcr2.dev/context/v1"
                  ],
                  "type": "DataIntegrityProof",
                  "cryptosuite": "bip340-jcs-2025",
                  "verificationMethod": "{{ verification-method }}",
                  "proofPurpose": "capabilityInvocation",
                  "capability": "{{ capability }}",
                  "capabilityAction": "Write"
                }
            """;

    private static final Logger log = LoggerFactory.getLogger(Update.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .build();

    private IPFSConnection ipfsConnection;

    public Update(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }

    /*
     * Update
     * See https://dcdpr.github.io/did-btcr2/operations/update.html
     */

    public Map<String, Object> update(BitcoinConnection bitcoinConnection, DIDDocument didSourceDocument, List<JsonPatch> jsonPatches, Integer targetVersionId, VerificationMethodPublicData verificationMethodPublicData, SigningResponse signingResponse, Map<String, Object> didDocumentMetadata) throws RegistrationException, UpdateGetVerificationMethodException, UpdateSignPayloadException {

        URI verificationMethodId = null;
        if (verificationMethodPublicData != null && verificationMethodPublicData.getId() != null) verificationMethodId = URI.create(verificationMethodPublicData.getId());
        if (signingResponse != null && signingResponse.getKid() != null) verificationMethodId = URI.create(signingResponse.getKid());

        /*
         * Construct BTCR2 Unsigned Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#construct-btcr2-unsigned-update
         */

        // Apply all JSON patches in jsonPatches to didSourceDocument to create didTargetDocument.

        DIDDocument didTargetDocument = didSourceDocument;
        for (JsonPatch jsonPatch : jsonPatches) didTargetDocument = JSONPatchUtil.apply(didTargetDocument, jsonPatch);

        // Fill the BTCR2 Unsigned Update (data structure) template below with the required template variables.

        String arrayOfPatchesString;
        try {
            arrayOfPatchesString = jsonMapper.writeValueAsString(jsonPatches);
        } catch (JsonProcessingException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot prepare array of patches: " + jsonPatches);
        }
        String updateString = BTCR2_UNSIGNED_UPDATE_TEMPLATE
                .replace("{{array-of-patches}}", arrayOfPatchesString)
                .replace("{{source-hash}}", Base64.getUrlEncoder().encodeToString(JSONDocumentHashing.jsonDocumentHashing(didSourceDocument)))
                .replace("{{target-hash}}", Base64.getUrlEncoder().encodeToString(JSONDocumentHashing.jsonDocumentHashing(didTargetDocument)))
                .replace("{{target-version-id}}", targetVersionId.toString());

        // Let update be the result of parsing the rendered template as JSON.

        BTCR2Update update = BTCR2Update.fromJson(updateString);

        /*
         * Construct BTCR2 Signed Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#construct-btcr2-signed-update
         */

        // An INVALID_DID_UPDATE error MUST be raised if the didSourceDocument.verificationMethod Set does not contain an id matching verificationMethodId.

        VerificationMethod verificationMethod = (VerificationMethod) JsonLDDereferencer.findByIdInJsonLdObject(didSourceDocument, verificationMethodId, null);
        if (! didSourceDocument.getVerificationMethods().contains(verificationMethod)) {
            throw new RegistrationException("INVALID_DID_UPDATE", "didSourceDocument.verificationMethod does not contain " + verificationMethodId);
        }

        // An INVALID_DID_UPDATE error MUST be raised if the didSourceDocument.capabilityInvocation Set does not contain verificationMethodId.

        if (! didSourceDocument.getCapabilityInvocationVerificationMethodsDereferenced().contains(verificationMethod)) {
            throw new RegistrationException("INVALID_DID_UPDATE", "didSourceDocument.capabilityInvocation does not contain " + verificationMethodId);
        }

        // Create cryptosuite as a BIP340 Cryptosuite [BIP340-Cryptosuite] instance with privateKey and "bip340-jcs-2025" cryptosuite.

        DataIntegrityProofLdSigner cryptosuite = new DataIntegrityProofLdSigner();
        cryptosuite.setCryptosuite("bip340-jcs-2025");

        // Fill the Data Integrity [VC-DATA-INTEGRITY] template below with the required template variables.

        cryptosuite.setVerificationMethod(verificationMethod.getId());
        cryptosuite.setProofPurpose("capabilityInvocation");
        cryptosuite.setCapability(URI.create("urn:zcap:root:" + URLEncoder.encode(didSourceDocument.getId().toString(), StandardCharsets.UTF_8)));
        cryptosuite.setCapabilityAction("Write");

        // Pass update and proofConfig to the cryptosuite.createProof method and set
        // update.proof to the resulting Data Integrity Proof (data structure).

        try {

            final byte[] signingResponseSignature = signingResponse == null ? null : Base64.getDecoder().decode(signingResponse.getSignature());
            final AtomicReference<byte[]> serializedPayload = new AtomicReference<>();

            if (verificationMethodId == null && signingResponseSignature == null) {
                throw new UpdateGetVerificationMethodException();
            }

            cryptosuite.setSigner(new ByteSigner(JWSAlgorithm.ES256K) {
                @Override
                protected byte[] sign(byte[] bytes) {
                    if (log.isDebugEnabled()) log.debug("Signing bytes {} with signing response signature {}", Hex.encodeHexString(bytes), Hex.encodeHexString(signingResponseSignature));
                    if (signingResponseSignature == null) {
                        serializedPayload.set(bytes);
                        return new byte[0];
                    } else {
                        return signingResponseSignature;
                    }
                }
            });

            cryptosuite.sign(update, true, false);

            if (serializedPayload.get() != null) {
                throw new UpdateSignPayloadException(verificationMethodId, serializedPayload.get());
            }
        } catch (IOException | GeneralSecurityException | JsonLDException ex) {
            throw new RegistrationException("Cannot sign the BTCR2 Update: " + ex.getMessage(), ex);
        }

        /*
         * Announce DID Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#announce-did-update
         */

        // TODO

        /*
         * Announcing to a Singleton Beacon
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#announcing-to-a-singleton-beacon
         */

        // A BTCR2 Update Announcement for a Singleton Beacon is the BTCR2 Signed Update hashed with the JSON Document Hashing algorithm.

        byte[] btcr2UpdateAnnouncement = JSONDocumentHashing.jsonDocumentHashing(update);

        // This 32-byte SHA-256 hash is used as the Signal Bytes when constructing a Beacon Signal Bitcoin transaction.

        // TODO fix selecting the correct service
        Service beaconService = didSourceDocument.getServices().stream().filter(service -> "SingletonBeacon".equals(service.getType()) && service.getId().toString().endsWith("#initialP2PKH")).findFirst().orElse(null);
        if (beaconService == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "No beacon service found in source DID document: " + didSourceDocument);
        String beaconServiceAddress;
        try {
            beaconServiceAddress = AddressUtil.bitcoinUriToAddressString((URI) beaconService.getServiceEndpoint());
        } catch (BitcoinURIParseException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "Invalid beacon service found in source DID document: " + beaconService);
        }
        List<TxOut> beaconServiceAddressUtxos = bitcoinConnection.getAddressUtxos(beaconServiceAddress);
        Script bitcoinjScript = ScriptBuilder.createOpReturnScript(btcr2UpdateAnnouncement);
        Transaction bitcoinjTransaction = new Transaction();
        for (TxOut beaconServiceAddressUtxo : beaconServiceAddressUtxos) {
            TransactionInput transactionInput;
            bitcoinjTransaction.addInput().addInput().addInput(beaconServiceAddressUtxo.to)
        }
        bitcoinjTransaction.addOutput(Coin.ZERO, bitcoinjScript);

        // The Beacon Signal is signed by the private key that controls the Beacon Address

        if (signPayloadResponse != null) {
            Script inputScript = ScriptBuilder.createInputScript(signature, pubKey);
            tx.getInput(0).setScriptSig(inputScript);
        } else {
            Sha256Hash hash = tx.hashForSignature(
                    inputIndex,
                    scriptPubKey,
                    Transaction.SigHash.ALL,
                    false
            );
        }

        // and broadcast to the Bitcoin network.

        byte[] beaconSignal = bitcoinjTransaction.serialize();
        if (log.isDebugEnabled()) log.debug("Broadcasting beacon signal: " + Hex.encodeHexString(beaconSignal));
        bitcoinConnection.broadcastRawTransaction(beaconSignal);

        /*
         * Announcing to an Aggregate Beacon
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#announcing-to-an-aggregate-beacon
         */

        // TODO

        // done

        return update.toMap();
    }

    /*
     * Helper classes
     */

    public static class UpdateGetVerificationMethodException extends Exception {

    }

    public static class UpdateSignPayloadException extends Exception {

        private final URI verificationMethodId;
        private final byte[] payload;

        public UpdateSignPayloadException(URI verificationMethodId, byte[] payload) {
            this.verificationMethodId = verificationMethodId;
            this.payload = payload;
        }

        public URI getVerificationMethodId() {
            return verificationMethodId;
        }

        public byte[] getPayload() {
            return payload;
        }
    }

    public static class BitcoinSignPayloadException extends Exception {

        private final URI verificationMethodId;
        private final byte[] payload;

        public UpdateSignPayloadException(URI verificationMethodId, byte[] payload) {
            this.verificationMethodId = verificationMethodId;
            this.payload = payload;
        }

        public URI getVerificationMethodId() {
            return verificationMethodId;
        }

        public byte[] getPayload() {
            return payload;
        }
    }

    /*
     * Getters and settes
     */

    public IPFSConnection getIpfsConnection() {
        return ipfsConnection;
    }

    public void setIpfsConnection(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }
}
