package uniregistrar.driver.did.btcr2.crud.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.records.TxOut;
import com.danubetech.btc.util.AddressUtil;
import com.danubetech.dataintegrity.jsonld.DataIntegrityKeywords;
import com.danubetech.dataintegrity.signer.DataIntegrityProofLdSigner;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.Service;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDDereferencer;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import fr.acinq.bitcoin.ByteVector32;
import fr.acinq.bitcoin.PublicKey;
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce;
import fr.acinq.bitcoin.crypto.musig2.Musig2;
import fr.acinq.bitcoin.crypto.musig2.SecretNonce;
import fr.acinq.bitcoin.utils.Either;
import kotlin.Pair;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.uri.BitcoinURIParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;
import uniregistrar.driver.did.btcr2.aggregation.AggregationService;
import uniregistrar.driver.did.btcr2.algorithms.JSONDocumentHashing;
import uniregistrar.driver.did.btcr2.beacons.BeaconType;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.util.BytesArray;
import uniregistrar.driver.did.btcr2.util.SHA256Util;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/*
 * Update
 * See https://dcdpr.github.io/did-btcr2/operations/update.html
 */

public class UpdateProcessUpdateSignPayload {

    private static final String BTCR2_UNSIGNED_UPDATE_TEMPLATE =
            """
                {
                  "@context": [
                    "https://btcr2.dev/context/v1",
                    "https://w3id.org/json-ld-patch/v1",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/security/data-integrity/v2"
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
                    "https://btcr2.dev/context/v1",
                    "https://w3id.org/json-ld-patch/v1",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/security/data-integrity/v2"
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

    private static final Logger log = LoggerFactory.getLogger(UpdateProcessUpdateSignPayload.class);

    private IPFSConnection ipfsConnection;

    public UpdateProcessUpdateSignPayload(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }

    public UpdateProcessUpdateSignPayloadResult update(BitcoinConnection bitcoinConnection, DID did, BTCR2Update update, URI verificationMethodId, DIDDocument didSourceDocument, URI beaconServiceId, String beaconServiceType, byte[] updateSignature, Map<String, Object> didDocumentMetadata) throws RegistrationException, UpdateActionFundAddressException, UpdateActionCompleteAggregationUpdatesException {

        /*
         * Construct BTCR2 Signed Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#construct-btcr2-signed-update
         */

        // An INVALID_DID_UPDATE error MUST be raised if the didSourceDocument.verificationMethod Set does not contain an id matching verificationMethodId.
        // An INVALID_DID_UPDATE error MUST be raised if the didSourceDocument.capabilityInvocation Set does not contain verificationMethodId.

        JsonLDObject verificationMethodJsonLDObject = JsonLDDereferencer.findByIdInJsonLdObject(didSourceDocument, verificationMethodId, didSourceDocument.getId());
        VerificationMethod verificationMethod = verificationMethodJsonLDObject == null ? null : VerificationMethod.fromJsonObject(verificationMethodJsonLDObject.getJsonObject());
        if (verificationMethod == null || ! didSourceDocument.getVerificationMethods().contains(verificationMethod)) {
            throw new RegistrationException("INVALID_DID_UPDATE", "didSourceDocument.verificationMethod does not contain " + verificationMethodId);
        }

        if (! didSourceDocument.getCapabilityInvocationVerificationMethodsDereferenced().contains(verificationMethod)) {
            throw new RegistrationException("INVALID_DID_UPDATE", "didSourceDocument.capabilityInvocation does not contain " + verificationMethodId);
        }

        // Create cryptosuite as a BIP340 Cryptosuite [BIP340-Cryptosuite] instance with privateKey and "bip340-jcs-2025" cryptosuite.

        DataIntegrityProofLdSigner cryptosuite = new DataIntegrityProofLdSigner();
        cryptosuite.setCryptosuite("bip340-jcs-2025");

        // Fill the Data Integrity [VC-DATA-INTEGRITY] template below with the required template variables.

        URI cryptosuiteVerificationMethod = verificationMethod.getId();
        if (! cryptosuiteVerificationMethod.isAbsolute()) cryptosuiteVerificationMethod = URI.create(didSourceDocument.getId() + cryptosuiteVerificationMethod.toString());
        URI cryptosuiteCapability = URI.create("urn:zcap:root:" + URLEncoder.encode(didSourceDocument.getId().toString(), StandardCharsets.UTF_8));

        cryptosuite.setVerificationMethod(cryptosuiteVerificationMethod);
        cryptosuite.setProofPurpose("capabilityInvocation");
        cryptosuite.setCapability(cryptosuiteCapability);
        cryptosuite.setCapabilityAction("Write");

        // Pass update and proofConfig to the cryptosuite.createProof method and set
        // update.proof to the resulting Data Integrity Proof (data structure).

        try {

            JsonLDUtils.jsonLdRemove(update, DataIntegrityKeywords.JSONLD_TERM_PROOF);

            cryptosuite.setSigner(new ByteSigner(JWSAlgorithm.ES256KS) {
                @Override
                protected byte[] sign(byte[] bytes) {
                    if (log.isDebugEnabled()) log.debug("Signing bytes {} with signing response signature {}", Hex.encodeHexString(bytes), Hex.encodeHexString(updateSignature));
                    return updateSignature;
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

        Stream<Service> serviceStream = didSourceDocument.getServices().stream();
        if (beaconServiceId != null) {
            serviceStream = serviceStream.filter(service -> {
                JsonLDObject didSourceDocumentService = JsonLDDereferencer.findByIdInJsonLdObject(didSourceDocument, beaconServiceId, didSourceDocument.getId());
                return didSourceDocumentService != null && didSourceDocumentService.getJsonObject() == service.getJsonObject();
            });
        }
        if (beaconServiceType != null) {
            serviceStream = serviceStream.filter(service -> beaconServiceType.equals(service.getType()));
        }
        serviceStream = serviceStream.filter(BeaconType::isValid);
        Service beaconService = serviceStream.findFirst().orElse(null);
        if (beaconService == null) beaconService = didSourceDocument.getServices() == null || didSourceDocument.getServices().isEmpty() ? null : didSourceDocument.getServices().getFirst();
        if (log.isDebugEnabled()) log.debug("beaconService for id {} and type {}: {}", beaconServiceId, beaconServiceType, beaconService);

        if (beaconService == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "No beacon service found in source DID document: " + didSourceDocument);
        if (! BeaconType.isValid(beaconService)) throw new RegistrationException("INVALID_DID_UPDATE", "Invalid beacon service: " + beaconService);

        UpdateProcessUpdateSignPayloadResult updateProcessUpdateSignPayloadResult = switch (BeaconType.fromServiceType(beaconService.getType())) {
            case SINGLETON -> announceToSingletonBeacon(bitcoinConnection, update, beaconService);
            case CAS, SMT -> announceToAggregateBeacon(bitcoinConnection, did, didSourceDocument, update, verificationMethodId, beaconService);
        };

        // result

        if (log.isDebugEnabled()) log.debug("Update: " + updateProcessUpdateSignPayloadResult);
        return updateProcessUpdateSignPayloadResult;
    }

    /*
     * Announcing to a Singleton Beacon
     * See https://dcdpr.github.io/did-btcr2/operations/update.html#announcing-to-a-singleton-beacon
     */

    private static UpdateProcessUpdateSignPayloadResult announceToSingletonBeacon(BitcoinConnection bitcoinConnection, BTCR2Update update, Service beaconService) throws RegistrationException, UpdateActionFundAddressException {

        // A BTCR2 Update Announcement for a Singleton Beacon is the BTCR2 Signed Update
        // hashed with the JSON Document Hashing algorithm.

        byte[] updateAnnouncement = JSONDocumentHashing.jsonDocumentHashing(update);
        if (log.isDebugEnabled()) log.debug("updateAnnouncement: " + Hex.encodeHexString(updateAnnouncement));

        // This 32-byte SHA-256 hash is used as the Signal Bytes when constructing a Beacon Signal Bitcoin transaction.

        byte[] signalBytes = updateAnnouncement;

        Address beaconAddress;
        try {
            beaconAddress = AddressUtil.bitcoinUriToBitcoinjAddress((URI) beaconService.getServiceEndpoint());
        } catch (BitcoinURIParseException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "Invalid beacon service found in source DID document: " + beaconService);
        }
        if (log.isDebugEnabled()) log.debug("beaconAddress: {}", beaconAddress);

        List<TxOut> beaconAddressUtxos = bitcoinConnection.getAddressUtxos(beaconAddress.toString());
        if (log.isDebugEnabled()) log.debug("beaconAddressUtxos: {}", beaconAddressUtxos);

        Coin totalValue = Coin.valueOf(beaconAddressUtxos.stream().mapToLong(TxOut::value).sum());
        if (log.isDebugEnabled()) log.debug("totalValue: {}", totalValue);
        if (totalValue.compareTo(BITCOIN_FEE) < 0) {
            // next state
            Coin minimumValue = BITCOIN_FEE.minus(totalValue);
            throw new UpdateActionFundAddressException(beaconAddress, minimumValue);
        }

        Transaction unsignedBeaconSignal = new Transaction();
        for (TxOut beaconAddressUtxo : beaconAddressUtxos) {
            unsignedBeaconSignal.addInput(Sha256Hash.wrap(beaconAddressUtxo.txIdBytes()), beaconAddressUtxo.txOutIndex(), Script.parse(beaconAddressUtxo.scriptBytes()));
        }
        unsignedBeaconSignal.addOutput(totalValue.minus(BITCOIN_FEE), beaconAddress);
        unsignedBeaconSignal.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript(signalBytes));
        if (log.isDebugEnabled()) log.debug("unsignedBeaconSignal before signing: {}", unsignedBeaconSignal);

        // The Beacon Signal is signed by the private key that controls the Beacon Address

        List<byte[]> utxoSingletonSignPayloads = IntStream.range(0, unsignedBeaconSignal.getInputs().size())
                .mapToObj(i -> unsignedBeaconSignal.hashForSignature(
                        i,
                        unsignedBeaconSignal.getInput(i).getScriptBytes(),
                        Transaction.SigHash.ALL,
                        false))
                .map(Sha256Hash::getBytes)
                .toList();

        // result

        return new UpdateProcessUpdateSignPayloadResult(update, unsignedBeaconSignal, utxoSingletonSignPayloads, null, null);
    }

    /*
     * Announcing to an Aggregate Beacon
     * See https://dcdpr.github.io/did-btcr2/operations/update.html#announcing-to-an-aggregate-beacon
     */

    private static UpdateProcessUpdateSignPayloadResult announceToAggregateBeacon(BitcoinConnection bitcoinConnection, DID did, DIDDocument didSourceDocument, BTCR2Update update, URI verificationMethodId, Service beaconService) throws RegistrationException, UpdateActionCompleteAggregationUpdatesException, UpdateActionFundAddressException {

        // find aggregation cohort

        AggregationCohort aggregationCohort = AggregationService.findByBeaconService(beaconService);
        if (aggregationCohort == null) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot find aggregation cohort for beacon service " + beaconService.getId());
        }

        // Aggregation Participants must submit a response to every update opportunity announced by the Aggregation Service;

        int participantIndex = aggregationCohort.findParticipantIndexByVerificationMethod(didSourceDocument, verificationMethodId);

        // For a CAS Beacon:
        // For an SMT Beacon:

        BeaconType beaconType = BeaconType.fromServiceType(beaconService.getType());

        switch (beaconType) {
            case CAS -> updateAggregateBeaconCAS(aggregationCohort, participantIndex, did, update);
            case SMT -> updateAggregateBeaconSMT(aggregationCohort, participantIndex, did, update, /* TODO */ null);
            default -> throw new IllegalStateException("Invalid beacon type: " + beaconType);
        };

        // Once responses to an update opportunity are collected

        if (! aggregationCohort.isUpdatesCompleted()) {
            // next state
            throw new UpdateActionCompleteAggregationUpdatesException(aggregationCohort);
        }

        // it aggregates the update announcements into an Unsigned Beacon Signal.

        if (! aggregationCohort.isUpdatesAggregated()) {
            aggregationCohort.aggregateUpdates(bitcoinConnection);
        }

        Transaction unsignedBeaconSignal = aggregationCohort.getUnsignedBeaconSignal();
        List<byte[]> utxoAggregateSignPayloads = aggregationCohort.getUtxoAggregateSignPayloads().get(participantIndex).stream().map(BytesArray::bytes).toList();

        // result

        return new UpdateProcessUpdateSignPayloadResult(update, unsignedBeaconSignal, null, utxoAggregateSignPayloads, aggregationCohort);
    }

    private static void updateAggregateBeaconCAS(AggregationCohort aggregationCohort, int participantIndex, DID did, BTCR2Update update) {

        // For a CAS Beacon:

        // did: The DID to be updated.

        aggregationCohort.setCasDid(participantIndex, did);

        // updateHash: The SHA-256 hash of the BTCR2 Update to be included, created with the JSON Document Hashing algorithm.

        byte[] updateHash = JSONDocumentHashing.jsonDocumentHashing(update);

        aggregationCohort.setCasUpdateHash(participantIndex, BytesArray.bytesArray(updateHash));

        // MuSig2 Nonce: A MuSig2 nonce constructed according to the nonce generation algorithm specified in [BIP327].

        SecureRandom random = new SecureRandom();
        //byte[] bytes = new byte[32];
        //random.nextBytes(bytes);
        byte[] bytes = SHA256Util.sha256("test".getBytes());
        ByteVector32 sessionId = new ByteVector32(bytes);
        PublicKey participantPublicKey = PublicKey.parse(aggregationCohort.getParticipantPublicKeys().get(participantIndex).bytes());
        List<PublicKey> participantPublicKeys = aggregationCohort.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(PublicKey::parse).toList();
        Pair<SecretNonce, IndividualNonce> pair = Musig2.generateNonce(sessionId, new Either.Right<PublicKey>(participantPublicKey), participantPublicKeys, null, null);

        aggregationCohort.setMusig2SecretNonce(participantIndex, BytesArray.bytesArray(pair.component1().getData$bitcoin_kmp().getBytes$bitcoin_kmp()));
        aggregationCohort.setMusig2IndividualNonce(participantIndex, BytesArray.bytesArray(pair.component2().toByteArray()));
    }

    private static void updateAggregateBeaconSMT(AggregationCohort aggregationCohort, int participantIndex, DID did, BTCR2Update update, byte[] nonce) {

        // For an SMT Beacon:

        // didIndex: The SHA-256 hash of the DID to be updated.

        byte[] didIndex = SHA256Util.sha256(did.getDidString().getBytes(StandardCharsets.UTF_8));

        aggregationCohort.setSmtDidIndex(participantIndex, BytesArray.bytesArray(didIndex));

        // updateHash:

        byte[] updateHash;

        if (nonce != null) {

            // If a nonce is used: hash(hash(nonce) + json_document_hash(update))

            byte[] bytes1 = SHA256Util.sha256(nonce);
            byte[] bytes2 = JSONDocumentHashing.jsonDocumentHashing(update);
            byte[] bytes = new byte[bytes1.length + bytes2.length];
            System.arraycopy(bytes1, 0, bytes, 0, bytes1.length);
            System.arraycopy(bytes2, 0, bytes, bytes1.length, bytes2.length);
            updateHash = SHA256Util.sha256(bytes);
        } else {

            // If a nonce is not used: json_document_hash(update)

            updateHash = JSONDocumentHashing.jsonDocumentHashing(update);
        }

        aggregationCohort.setSmtUpdateHash(participantIndex, BytesArray.bytesArray(updateHash));
        aggregationCohort.setSmtNonce(participantIndex, nonce != null ? BytesArray.bytesArray(nonce) : BytesArray.bytesArray(new byte[0]));

        // MuSig2 Nonce: A MuSig2 nonce constructed according to the nonce generation algorithm specified in [BIP327].

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        ByteVector32 sessionId = new ByteVector32(bytes);
        PublicKey participantPublicKey = PublicKey.parse(aggregationCohort.getParticipantPublicKeys().get(participantIndex).bytes());
        List<PublicKey> participantPublicKeys = aggregationCohort.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(PublicKey::parse).toList();
        Pair<SecretNonce, IndividualNonce> pair = Musig2.generateNonce(sessionId, new Either.Right<PublicKey>(participantPublicKey), participantPublicKeys, null, null);

        aggregationCohort.setMusig2SecretNonce(participantIndex, BytesArray.bytesArray(pair.component1().getData$bitcoin_kmp().getBytes$bitcoin_kmp()));
        aggregationCohort.setMusig2IndividualNonce(participantIndex, BytesArray.bytesArray(pair.component2().toByteArray()));
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
