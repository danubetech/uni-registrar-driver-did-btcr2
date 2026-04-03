package uniregistrar.driver.did.btcr2.crud.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.records.TxOut;
import com.danubetech.btc.util.AddressUtil;
import com.danubetech.dataintegrity.signer.DataIntegrityProofLdSigner;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.Service;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDDereferencer;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import jakarta.json.JsonPatch;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.crypto.ECKey;
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

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;

/*
 * Update
 * See https://dcdpr.github.io/did-btcr2/operations/update.html
 */

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

    private static final Coin BITCOIN_FEE = Coin.valueOf(100);

    private static final Logger log = LoggerFactory.getLogger(Update.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .build();

    private IPFSConnection ipfsConnection;

    public Update(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }

    public UpdateInitResult updateInit(BitcoinConnection bitcoinConnection, DIDDocument didSourceDocument, Integer targetVersionId, JsonPatch jsonPatches, URI verificationMethodId, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        /*
         * Construct BTCR2 Unsigned Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#construct-btcr2-unsigned-update
         */

        // Apply all JSON patches in jsonPatches to didSourceDocument to create didTargetDocument.

        DIDDocument didTargetDocument = didSourceDocument;
        didTargetDocument = JSONPatchUtil.apply(didTargetDocument, jsonPatches);
        if (log.isDebugEnabled()) log.debug("didTargetDocument: " + didTargetDocument);

        // Fill the BTCR2 Unsigned Update (data structure) template below with the required template variables.

        String arrayOfPatchesString;
        try {
            arrayOfPatchesString = jsonMapper.writeValueAsString(jsonPatches.toJsonArray());
        } catch (JsonProcessingException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot prepare array of patches: " + ex.getMessage(), ex);
        }
        String updateString = BTCR2_UNSIGNED_UPDATE_TEMPLATE
                .replace("{{array-of-patches}}", arrayOfPatchesString)
                .replace("{{source-hash}}", Base64.getUrlEncoder().encodeToString(JSONDocumentHashing.jsonDocumentHashing(didSourceDocument)))
                .replace("{{target-hash}}", Base64.getUrlEncoder().encodeToString(JSONDocumentHashing.jsonDocumentHashing(didTargetDocument)))
                .replace("{{target-version-id}}", targetVersionId.toString());
        if (log.isDebugEnabled()) log.debug("updateString: " + updateString);

        // Let update be the result of parsing the rendered template as JSON.

        BTCR2Update update = BTCR2Update.fromJson(updateString);
        if (log.isDebugEnabled()) log.debug("update: " + update);

        /*
         * Construct BTCR2 Signed Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#construct-btcr2-signed-update
         */

        // An INVALID_DID_UPDATE error MUST be raised if the didSourceDocument.verificationMethod Set does not contain an id matching verificationMethodId.
        // An INVALID_DID_UPDATE error MUST be raised if the didSourceDocument.capabilityInvocation Set does not contain verificationMethodId.

        JsonLDObject verificationMethodJsonLDObject = JsonLDDereferencer.findByIdInJsonLdObject(didSourceDocument, verificationMethodId, didSourceDocument.getId());
        VerificationMethod verificationMethod = verificationMethodJsonLDObject == null ? null : VerificationMethod.fromJsonObject(verificationMethodJsonLDObject.getJsonObject());
        if (! didSourceDocument.getVerificationMethods().contains(verificationMethod)) {
            throw new RegistrationException("INVALID_DID_UPDATE", "didSourceDocument.verificationMethod does not contain " + verificationMethodId);
        }

        if (! didSourceDocument.getCapabilityInvocationVerificationMethodsDereferenced().contains(verificationMethod)) {
            throw new RegistrationException("INVALID_DID_UPDATE", "didSourceDocument.capabilityInvocation does not contain " + verificationMethodId);
        }

        // Create cryptosuite as a BIP340 Cryptosuite [BIP340-Cryptosuite] instance with privateKey and "bip340-jcs-2025" cryptosuite.

        DataIntegrityProofLdSigner cryptosuite = new DataIntegrityProofLdSigner();
        cryptosuite.setCryptosuite("bip340-jcs-2025");

        // Fill the Data Integrity [VC-DATA-INTEGRITY] template below with the required template variables.

        cryptosuite.setVerificationMethod(verificationMethodJsonLDObject.getId());
        cryptosuite.setProofPurpose("capabilityInvocation");
        cryptosuite.setCapability(URI.create("urn:zcap:root:" + URLEncoder.encode(didSourceDocument.getId().toString(), StandardCharsets.UTF_8)));
        cryptosuite.setCapabilityAction("Write");

        // Pass update and proofConfig to the cryptosuite.createProof method and set
        // update.proof to the resulting Data Integrity Proof (data structure).

        byte[] updateSignPayload;

        try {

            final AtomicReference<byte[]> reference = new AtomicReference<>();

            cryptosuite.setSigner(new ByteSigner(JWSAlgorithm.ES256KS) {
                @Override
                protected byte[] sign(byte[] bytes) {
                    if (log.isDebugEnabled()) log.debug("Signing bytes {}", Hex.encodeHexString(bytes));
                    reference.set(bytes);
                    return new byte[0];
                }
            });
            cryptosuite.sign(update, true, false);

            updateSignPayload = reference.get();
        } catch (IOException | GeneralSecurityException | JsonLDException ex) {
            throw new RegistrationException("Cannot sign the BTCR2 Update: " + ex.getMessage(), ex);
        }

        // result

        UpdateInitResult updateInitResult = new UpdateInitResult(verificationMethodId, updateSignPayload);
        if (log.isDebugEnabled()) log.debug("Update: " + updateInitResult);
        return updateInitResult;
    }

    public UpdateProcessUpdateSignPayloadResult updateProcessUpdateSignPayload(BitcoinConnection bitcoinConnection, DIDDocument didSourceDocument, Integer targetVersionId, JsonPatch jsonPatches, URI verificationMethodId, byte[] updateSigningResponseSignature, Map<String, Object> didDocumentMetadata) throws RegistrationException, UpdateActionFundAddressException {

        /*
         * Construct BTCR2 Unsigned Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#construct-btcr2-unsigned-update
         */

        // Apply all JSON patches in jsonPatches to didSourceDocument to create didTargetDocument.

        DIDDocument didTargetDocument = didSourceDocument;
        didTargetDocument = JSONPatchUtil.apply(didTargetDocument, jsonPatches);
        if (log.isDebugEnabled()) log.debug("didTargetDocument: " + didTargetDocument);

        // Fill the BTCR2 Unsigned Update (data structure) template below with the required template variables.

        String arrayOfPatchesString;
        try {
            arrayOfPatchesString = jsonMapper.writeValueAsString(jsonPatches.toJsonArray());
        } catch (JsonProcessingException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot prepare array of patches: " + ex.getMessage(), ex);
        }
        String updateString = BTCR2_UNSIGNED_UPDATE_TEMPLATE
                .replace("{{array-of-patches}}", arrayOfPatchesString)
                .replace("{{source-hash}}", Base64.getUrlEncoder().encodeToString(JSONDocumentHashing.jsonDocumentHashing(didSourceDocument)))
                .replace("{{target-hash}}", Base64.getUrlEncoder().encodeToString(JSONDocumentHashing.jsonDocumentHashing(didTargetDocument)))
                .replace("{{target-version-id}}", targetVersionId.toString());
        if (log.isDebugEnabled()) log.debug("updateString: " + updateString);

        // Let update be the result of parsing the rendered template as JSON.

        BTCR2Update update = BTCR2Update.fromJson(updateString);
        if (log.isDebugEnabled()) log.debug("update: " + update);

        /*
         * Construct BTCR2 Signed Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#construct-btcr2-signed-update
         */

        // An INVALID_DID_UPDATE error MUST be raised if the didSourceDocument.verificationMethod Set does not contain an id matching verificationMethodId.
        // An INVALID_DID_UPDATE error MUST be raised if the didSourceDocument.capabilityInvocation Set does not contain verificationMethodId.

        JsonLDObject verificationMethodJsonLDObject = JsonLDDereferencer.findByIdInJsonLdObject(didSourceDocument, verificationMethodId, didSourceDocument.getId());
        VerificationMethod verificationMethod = verificationMethodJsonLDObject == null ? null : VerificationMethod.fromJsonObject(verificationMethodJsonLDObject.getJsonObject());
        if (! didSourceDocument.getVerificationMethods().contains(verificationMethod)) {
            throw new RegistrationException("INVALID_DID_UPDATE", "didSourceDocument.verificationMethod does not contain " + verificationMethodId);
        }

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

            cryptosuite.setSigner(new ByteSigner(JWSAlgorithm.ES256KS) {
                @Override
                protected byte[] sign(byte[] bytes) {
                    if (log.isDebugEnabled()) log.debug("Signing bytes {} with signing response signature {}", Hex.encodeHexString(bytes), Hex.encodeHexString(updateSigningResponseSignature));
                    return updateSigningResponseSignature;
                }
            });

            cryptosuite.sign(update, true, false);
        } catch (IOException | GeneralSecurityException | JsonLDException ex) {
            throw new RegistrationException("Cannot sign the BTCR2 Update: " + ex.getMessage(), ex);
        }

        /*
         * Announce DID Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#announce-did-update
         */

        // BTCR2 Signed Updates are announced to the Bitcoin blockchain depending on the Beacon Type.

        /*
         * Announcing to a Singleton Beacon
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#announcing-to-a-singleton-beacon
         */

        // A BTCR2 Update Announcement for a Singleton Beacon is the BTCR2 Signed Update
        // hashed with the JSON Document Hashing algorithm.

        byte[] btcr2UpdateAnnouncement = JSONDocumentHashing.jsonDocumentHashing(update);
        if (log.isDebugEnabled()) log.debug("btcr2UpdateAnnouncement: " + Hex.encodeHexString(btcr2UpdateAnnouncement));

        // This 32-byte SHA-256 hash is used as the Signal Bytes when constructing a Beacon Signal Bitcoin transaction.

        // TODO fix selecting the correct service
        Service beaconService = didSourceDocument.getServices().stream().filter(service -> "SingletonBeacon".equals(service.getType()) && service.getId().toString().endsWith("#initialP2PKH")).findFirst().orElse(null);
        if (beaconService == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "No beacon service found in source DID document: " + didSourceDocument);
        if (log.isDebugEnabled()) log.debug("beaconService: {}", beaconService);

        Address beaconServiceAddress;
        try {
            beaconServiceAddress = AddressUtil.bitcoinUriToBitcoinjAddress((URI) beaconService.getServiceEndpoint());
        } catch (BitcoinURIParseException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "Invalid beacon service found in source DID document: " + beaconService);
        }
        if (log.isDebugEnabled()) log.debug("beaconServiceAddress: {}", beaconServiceAddress);

        List<TxOut> beaconServiceAddressUtxos = bitcoinConnection.getAddressUtxos(beaconServiceAddress.toString());
        if (log.isDebugEnabled()) log.debug("beaconServiceAddressUtxos: {}", beaconServiceAddressUtxos);

        Coin totalValue = Coin.valueOf(beaconServiceAddressUtxos.stream().mapToLong(TxOut::value).sum());
        if (log.isDebugEnabled()) log.debug("totalValue: {}", totalValue);
        if (totalValue.compareTo(BITCOIN_FEE) < 0) {
            throw new UpdateActionFundAddressException(beaconServiceAddress, BITCOIN_FEE.minus(totalValue));
        }

        Transaction bitcoinjTransaction = new Transaction();
        for (TxOut beaconServiceAddressUtxo : beaconServiceAddressUtxos) {
            bitcoinjTransaction.addInput(Sha256Hash.wrap(beaconServiceAddressUtxo.txIdBytes()), beaconServiceAddressUtxo.txOutIndex(), Script.parse(beaconServiceAddressUtxo.scriptBytes()));
        }
        bitcoinjTransaction.addOutput(totalValue.minus(BITCOIN_FEE), beaconServiceAddress);
        bitcoinjTransaction.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript(btcr2UpdateAnnouncement));
        if (log.isDebugEnabled()) log.debug("bitcoinjTransaction before signing: {}", bitcoinjTransaction);

        // The Beacon Signal is signed by the private key that controls the Beacon Address

        List<byte[]> utxoSignPayloads = IntStream.range(0, bitcoinjTransaction.getInputs().size())
                .mapToObj(i -> bitcoinjTransaction.hashForSignature(
                        i,
                        bitcoinjTransaction.getInput(i).getScriptBytes(),
                        Transaction.SigHash.ALL,
                        false))
                .map(Sha256Hash::getBytes)
                .toList();

        // result

        UpdateProcessUpdateSignPayloadResult updateProcessUpdateSignPayloadResult = new UpdateProcessUpdateSignPayloadResult(btcr2UpdateAnnouncement, utxoSignPayloads);
        if (log.isDebugEnabled()) log.debug("Update: " + updateProcessUpdateSignPayloadResult);
        return updateProcessUpdateSignPayloadResult;
    }

    public UpdateProcessUtxoSignPayloadsResult updateProcessUtxoSignPayloads(BitcoinConnection bitcoinConnection, DID did, DIDDocument didSourceDocument, Integer targetVersionId, JsonPatch jsonPatches, byte[] btcr2UpdateAnnouncement, ECKey updateECKey, List<byte[]> utxoSigningResponseSignatures, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        /*
         * Announce DID Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#announce-did-update
         */

        // BTCR2 Signed Updates are announced to the Bitcoin blockchain depending on the Beacon Type.

        /*
         * Announcing to a Singleton Beacon
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#announcing-to-a-singleton-beacon
         */

        // This 32-byte SHA-256 hash is used as the Signal Bytes when constructing a Beacon Signal Bitcoin transaction.

        // TODO fix selecting the correct service
        Service beaconService = didSourceDocument.getServices().stream().filter(service -> "SingletonBeacon".equals(service.getType()) && service.getId().toString().endsWith("#initialP2PKH")).findFirst().orElse(null);
        if (beaconService == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "No beacon service found in source DID document: " + didSourceDocument);
        if (log.isDebugEnabled()) log.debug("beaconService: {}", beaconService);

        Address beaconServiceAddress;
        try {
            beaconServiceAddress = AddressUtil.bitcoinUriToBitcoinjAddress((URI) beaconService.getServiceEndpoint());
        } catch (BitcoinURIParseException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "Invalid beacon service found in source DID document: " + beaconService);
        }
        if (log.isDebugEnabled()) log.debug("beaconServiceAddress: {}", beaconServiceAddress);

        List<TxOut> beaconServiceAddressUtxos = bitcoinConnection.getAddressUtxos(beaconServiceAddress.toString());
        if (log.isDebugEnabled()) log.debug("beaconServiceAddressUtxos: {}", beaconServiceAddressUtxos);

        Coin totalValue = Coin.valueOf(beaconServiceAddressUtxos.stream().mapToLong(TxOut::value).sum());
        if (log.isDebugEnabled()) log.debug("totalValue: {}", totalValue);
        if (totalValue.compareTo(BITCOIN_FEE) < 0) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Insufficient funds on " + beaconServiceAddress + ": " + totalValue + "/" + BITCOIN_FEE);
        }

        Transaction bitcoinjTransaction = new Transaction();
        for (TxOut beaconServiceAddressUtxo : beaconServiceAddressUtxos) {
            bitcoinjTransaction.addInput(Sha256Hash.wrap(beaconServiceAddressUtxo.txIdBytes()), beaconServiceAddressUtxo.txOutIndex(), Script.parse(beaconServiceAddressUtxo.scriptBytes()));
        }
        bitcoinjTransaction.addOutput(totalValue.minus(BITCOIN_FEE), beaconServiceAddress);
        bitcoinjTransaction.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript(btcr2UpdateAnnouncement));
        if (log.isDebugEnabled()) log.debug("bitcoinjTransaction before signing: {}", bitcoinjTransaction);

        // The Beacon Signal is signed by the private key that controls the Beacon Address

        for (int i=0; i<bitcoinjTransaction.getInputs().size(); i++) {
            TransactionInput transactionInput = bitcoinjTransaction.getInput(i);
            byte[] utxoSigningResponseSignature = utxoSigningResponseSignatures.get(i);
            byte[] r = new byte[32];
            byte[] s = new byte[32];
            System.arraycopy(utxoSigningResponseSignature, 0, r, 0, r.length);
            System.arraycopy(utxoSigningResponseSignature, 32, s, 0, s.length);
            ECKey.ECDSASignature signature = new ECKey.ECDSASignature(new BigInteger(1, r), new BigInteger(1, s));
            TransactionSignature transactionSignature = new TransactionSignature(signature, Transaction.SigHash.ALL, false);
            TransactionInput signedTransactionInput = transactionInput.withScriptSig(ScriptBuilder.createInputScript(transactionSignature, updateECKey));
            bitcoinjTransaction.replaceInput(i, signedTransactionInput);
        }
        if (log.isDebugEnabled()) log.debug("bitcoinjTransaction after signing: {}", bitcoinjTransaction);

        // and broadcast to the Bitcoin network.

        byte[] beaconSignal = bitcoinjTransaction.serialize();
        if (log.isDebugEnabled()) log.debug("Broadcasting beacon signal: " + Hex.encodeHexString(beaconSignal));
        bitcoinConnection.broadcastRawTransaction(beaconSignal);

        /*
         * Announcing to an Aggregate Beacon
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#announcing-to-an-aggregate-beacon
         */

        // result

        UpdateProcessUtxoSignPayloadsResult updateProcessUtxoSignPayloadsResult = new UpdateProcessUtxoSignPayloadsResult(did);
        if (log.isDebugEnabled()) log.debug("Update: " + updateProcessUtxoSignPayloadsResult);
        return updateProcessUtxoSignPayloadsResult;
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
