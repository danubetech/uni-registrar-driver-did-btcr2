package uniregistrar.driver.did.btcr2.crud.update;

import com.danubetech.btc.connection.BitcoinConnection;
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
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.SignatureDecodeException;
import org.bitcoinj.crypto.TransactionSignature;
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
import java.util.stream.IntStream;

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

    public Map<String, Object> update(BitcoinConnection bitcoinConnection, DIDDocument didSourceDocument, List<JsonPatch> jsonPatches, Integer targetVersionId, VerificationMethodPublicData updateVerificationMethodPublicData, SigningResponse updateSigningResponse, List<SigningResponse> utxoSigningResponses, Map<String, Object> didDocumentMetadata) throws RegistrationException, UpdateGetVerificationMethodException, UpdateSignPayloadException, UtxoSignPayloadException {

        URI verificationMethodId = null;
        if (updateVerificationMethodPublicData != null && updateVerificationMethodPublicData.getId() != null) verificationMethodId = URI.create(updateVerificationMethodPublicData.getId());
        if (updateSigningResponse != null && updateSigningResponse.getKid() != null) verificationMethodId = URI.create(updateSigningResponse.getKid());

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

            final byte[] updateSigningResponseSignature = updateSigningResponse == null ? null : Base64.getDecoder().decode(updateSigningResponse.getSignature());
            final AtomicReference<byte[]> updateSerializedPayload = new AtomicReference<>();

            if (verificationMethodId == null && updateSigningResponseSignature == null) {
                throw new UpdateGetVerificationMethodException();
            }

            cryptosuite.setSigner(new ByteSigner(JWSAlgorithm.ES256K) {
                @Override
                protected byte[] sign(byte[] bytes) {
                    if (log.isDebugEnabled()) log.debug("Signing bytes {} with signing response signature {}", Hex.encodeHexString(bytes), Hex.encodeHexString(updateSigningResponseSignature));
                    if (updateSigningResponseSignature == null) {
                        updateSerializedPayload.set(bytes);
                        return new byte[0];
                    } else {
                        return updateSigningResponseSignature;
                    }
                }
            });

            cryptosuite.sign(update, true, false);

            if (updateSerializedPayload.get() != null) {
                throw new UpdateSignPayloadException(verificationMethodId, updateSerializedPayload.get());
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

        Address beaconServiceAddress;
        try {
            beaconServiceAddress = AddressUtil.bitcoinUriToBitcoinjAddress((URI) beaconService.getServiceEndpoint());
        } catch (BitcoinURIParseException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "Invalid beacon service found in source DID document: " + beaconService);
        }

        List<TxOut> beaconServiceAddressUtxos = bitcoinConnection.getAddressUtxos(beaconServiceAddress.toString());

        Transaction bitcoinjTransaction = new Transaction();
        long totalValue = 0;
        for (TxOut beaconServiceAddressUtxo : beaconServiceAddressUtxos) {
            TransactionOutput transactionOutput = new TransactionOutput(null, Coin.valueOf(beaconServiceAddressUtxo.value()), beaconServiceAddressUtxo.scriptBytes());
            bitcoinjTransaction.addInput(transactionOutput);
            totalValue += beaconServiceAddressUtxo.value();
        }
        bitcoinjTransaction.addOutput(Coin.valueOf(totalValue), beaconServiceAddress);
        bitcoinjTransaction.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript(btcr2UpdateAnnouncement));

        // The Beacon Signal is signed by the private key that controls the Beacon Address

        try {

            List<byte[]> utxoSigningResponseSignatures = utxoSigningResponses == null ? null : utxoSigningResponses.stream().map(SigningResponse::getSignature).map(signature -> Base64.getDecoder().decode(signature)).toList();
            if (utxoSigningResponseSignatures == null || utxoSigningResponseSignatures.size() != bitcoinjTransaction.getInputs().size()) {
                List<byte[]> payloads = IntStream.range(0, bitcoinjTransaction.getInputs().size())
                        .mapToObj(i -> bitcoinjTransaction.hashForSignature(
                                i,
                                bitcoinjTransaction.getInput(i).getScriptBytes(),
                                Transaction.SigHash.ALL,
                                false))
                        .map(Sha256Hash::getBytes)
                        .toList();
                throw new UtxoSignPayloadException(payloads);
            }

            for (int i=0; i<bitcoinjTransaction.getInputs().size(); i++) {
                TransactionInput transactionInput = bitcoinjTransaction.getInput(i);
                byte[] utxoSigningResponseSignature = utxoSigningResponseSignatures.get(i);
                TransactionSignature transactionSignature = new TransactionSignature(
                        ECKey.ECDSASignature.decodeFromDER(utxoSigningResponseSignature /* TODO, not DER */),
                        Transaction.SigHash.ALL,
                        false);
                transactionInput = transactionInput.withScriptSig(ScriptBuilder.createInputScript(transactionSignature, null /* TODO key */));
            }

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
        } catch (IOException | GeneralSecurityException | JsonLDException | SignatureDecodeException ex) {
            throw new RegistrationException("Cannot sign the Bitcoin transaction: " + ex.getMessage(), ex);
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

    public static class UtxoSignPayloadException extends Exception {

        private final List<byte[]> payloads;

        public UtxoSignPayloadException(List<byte[]> payloads) {
            this.payloads = payloads;
        }

        public List<byte[]> getPayloads() {
            return payloads;
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
