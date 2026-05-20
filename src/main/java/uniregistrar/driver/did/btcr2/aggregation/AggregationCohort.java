package uniregistrar.driver.did.btcr2.aggregation;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.BitcoinConnector;
import com.danubetech.btc.connection.Network;
import com.danubetech.btc.connection.records.TxOut;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDDereferencer;
import foundation.identity.jsonld.JsonLDObject;
import fr.acinq.bitcoin.*;
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce;
import fr.acinq.bitcoin.crypto.musig2.Musig2;
import fr.acinq.bitcoin.utils.Either;
import io.ipfs.multibase.Multibase;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.*;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.uri.BitcoinURI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.appendix.JsonCanonicalizationAndHash;
import uniregistrar.driver.did.btcr2.beacons.BeaconType;
import uniregistrar.driver.did.btcr2.crud.update.UpdateActionFundAddressException;
import uniregistrar.driver.did.btcr2.data.CASAnnouncement;
import uniregistrar.driver.did.btcr2.data.SMTProof;
import uniregistrar.driver.did.btcr2.data.SmtProof;
import uniregistrar.driver.did.btcr2.data.SparseMerkleTree;
import uniregistrar.driver.did.btcr2.util.BytesArray;
import uniregistrar.driver.did.btcr2.util.MultiCodecUtil;
import uniregistrar.driver.did.btcr2.util.SHA256Util;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

public class AggregationCohort {

    private static final Logger log = LoggerFactory.getLogger(AggregationCohort.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .build();

    private static final Coin BITCOIN_FEE = Coin.valueOf(100);

    private final String id;
    private final Network network;
    private final int maxSize;
    private final BeaconType beaconType;
    private final ScriptType scriptType;

    private ArrayList<BytesArray> participantPublicKeys = new ArrayList<>();

    private Address beaconAddress;
    private byte[] musig2NonceSessionId;

    // For a CAS Beacon:

    private Map<Integer, DID> casDids = new TreeMap<>();
    private Map<Integer, BytesArray> casUpdateHashes = new TreeMap<>();

    // For an SMT Beacon:

    private Map<Integer, BytesArray> smtDidIndexes = new TreeMap<>();
    private Map<Integer, BytesArray> smtUpdateHashes = new TreeMap<>();

    // For a CAS Beacon:
    // For an SMT Beacon:

    private Map<Integer, BytesArray> musig2SecretNonces = new TreeMap<>();
    private Map<Integer, BytesArray> musig2PublicNonces = new TreeMap<>();

    // For a CAS Beacon, the request signal confirmation message contains:

    private LinkedHashMap<DID, BytesArray> casBeaconAnnouncementMap = new LinkedHashMap<>();

    // For an SMT Beacon, the request signal confirmation message contains:

    private LinkedHashMap<BytesArray, SmtProof> smtProofs = new LinkedHashMap<>();

    // For a CAS Beacon, the request signal confirmation message contains:
    // For an SMT Beacon, the request signal confirmation message contains:

    private Transaction unsignedBeaconSignal;
    private byte[] musig2AggregatedNonce;

    private byte[] signalBytes;
    private List<TxOut> beaconAddressUtxos;
    private Map<Integer, List<BytesArray>> utxoAggregateSignPayloads;

    private Map<Integer, List<BytesArray>> utxoAggregateSignatures = new TreeMap<>();

    private List<BytesArray> musig2AggregatedSignatures;

    private String broadcastRawTransactionId;

    public AggregationCohort(String id, Network network, int maxSize, BeaconType beaconType, ScriptType scriptType) {
        this.id = id;
        this.network = network;
        this.maxSize = maxSize;
        this.beaconType = beaconType;
        this.scriptType = scriptType;
    }

    public Map<String, Object> getMetadata() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("id", this.getId());
        metadata.put("network", this.getNetwork().toString());
        metadata.put("beaconType", this.getBeaconType().toString());
        metadata.put("scriptType", this.getScriptType().toString());
        metadata.put("maxSize", this.getMaxSize());
        Map<String, Object> metadataCohort = (Map<String, Object>) metadata.computeIfAbsent("cohort", x -> new LinkedHashMap<>());
        metadataCohort.put("cohortSize", this.cohortSize());
        metadataCohort.put("isCohortCompleted", this.isCohortCompleted());
        metadataCohort.put("isCohortFinalized", this.isCohortFinalized());
        metadataCohort.put("participantPublicKeys", this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList());
        metadataCohort.put("beaconAddress", this.getBeaconAddress() == null ? null : this.getBeaconAddress().toString());
        metadataCohort.put("musig2NonceSessionId", this.getMusig2NonceSessionId() == null ? null : Hex.encodeHexString(this.getMusig2NonceSessionId()));
        Map<String, Object> metadataUpdates = (Map<String, Object>) metadata.computeIfAbsent("updates", x -> new LinkedHashMap<>());
        metadataUpdates.put("updatesSize", this.updatesSize());
        metadataUpdates.put("isUpdatesCompleted", this.isUpdatesCompleted());
        metadataUpdates.put("isUpdatesAggregated", this.isUpdatesAggregated());
        metadataUpdates.put("updateHashes", this.getUpdatesHashes().stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList());
        metadataUpdates.put("unsignedBeaconSignal", this.getUnsignedBeaconSignal() == null ? null : Hex.encodeHexString(this.getUnsignedBeaconSignal().serialize()));
        metadataUpdates.put("musig2AggregatedNonce", this.getMusig2AggregatedNonce() == null ? null : Hex.encodeHexString(this.getMusig2AggregatedNonce()));
        metadataUpdates.put("signalBytes", this.getSignalBytes() == null ? null : Hex.encodeHexString(this.getSignalBytes()));
        metadataUpdates.put("beaconAddressUtxos", this.getBeaconAddressUtxos() == null ? null : this.getBeaconAddressUtxos().stream().map(TxOut::txId).toList());
        metadataUpdates.put("utxoAggregateSignPayloads", this.getUtxoAggregateSignPayloads() == null ? null : this.getUtxoAggregateSignPayloads().values().stream().map(x -> x.stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList()).toList());
        Map<String, Object> metadataSignatures = (Map<String, Object>) metadata.computeIfAbsent("signatures", x -> new LinkedHashMap<>());
        metadataSignatures.put("signaturesSize", this.signaturesSize());
        metadataSignatures.put("isSignaturesCompleted", this.isSignaturesCompleted());
        metadataSignatures.put("isSignaturesAggregated", this.isSignaturesAggregated());
        metadataSignatures.put("utxoAggregateSignatures", this.getUtxoAggregateSignatures() == null ? null : this.getUtxoAggregateSignatures().values().stream().map(x -> x.stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList()).toList());
        metadataSignatures.put("musig2AggregatedSignatures", this.getMusig2AggregatedSignatures() == null ? null : this.getMusig2AggregatedSignatures().stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList());
        metadata.put("broadcastRawTransactionId", this.getBroadcastRawTransactionId());
        return Map.of("aggregationCohort", metadata);
    }

    /*
     * Step 1: Create Aggregation Cohort
     * See https://dcdpr.github.io/did-btcr2/beacons/aggregate-beacons.html#step-1-create-aggregation-cohort
     */

    public int cohortSize() {
        return this.getParticipantPublicKeys().size();
    }

    public boolean isCohortCompleted() {
        boolean cohortCompleted = this.cohortSize() >= this.getMaxSize();
        if (log.isDebugEnabled()) log.debug("cohortCompleted? {}", cohortCompleted);
        return cohortCompleted;
    }

    public boolean isCohortFinalized() {
        boolean cohortFinalized = this.getBeaconAddress() != null;
        if (log.isDebugEnabled()) log.debug("cohortFinalized? {}", cohortFinalized);
        return cohortFinalized;
    }

    public void finalizeCohort(BitcoinConnector bitcoinConnector) {

        if (! this.isCohortCompleted()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet completed.");
        if (this.isCohortFinalized()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " already finalized.");

        this.beaconAddress = switch (this.getScriptType()) {
            case P2SH -> {
                List<ECKey> publicKeys = new ArrayList<>(this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(ECKey::fromPublicOnly).toList());
                publicKeys.sort(ECKey.PUBKEY_COMPARATOR);
                Script script = ScriptBuilder.createRedeemScript(this.getParticipantPublicKeys().size(), publicKeys);
                yield LegacyAddress.fromScriptHash(this.getNetwork().toBitcoinjNetwork(), ScriptPattern.extractHashFromP2SH(script));
            }
            case P2WSH -> {
                List<ECKey> publicKeys = new ArrayList<>(this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(ECKey::fromPublicOnly).toList());
                publicKeys.sort(ECKey.PUBKEY_COMPARATOR);
                Script script = ScriptBuilder.createRedeemScript(this.getParticipantPublicKeys().size(), publicKeys);
                yield LegacyAddress.fromScriptHash(this.getNetwork().toBitcoinjNetwork(), ScriptPattern.extractHashFromP2PKH(script));
            }
            case P2TR -> {
                List<PublicKey> publicKeys = this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(PublicKey::parse).toList();
                XonlyPublicKey aggregatePublicKey = Musig2.aggregateKeys(publicKeys);
                aggregatePublicKey.tweak(Crypto.TaprootTweak.KeyPathTweak.INSTANCE);
                yield AddressParser.getDefault().parseAddress(aggregatePublicKey.p2trAddress(new BlockHash(bitcoinConnector.getGenesisHash(this.getNetwork()))));
            }
            default -> throw new IllegalStateException("Invalid script type, not supported for aggregation cohort: " + this.getScriptType());
        };

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        this.musig2NonceSessionId = bytes;

        if (log.isDebugEnabled()) log.debug("For script tyoe " + this.getScriptType() + " and size " + this.cohortSize() + " finalized cohort with beacon address " + this.getBeaconAddress() + " and nonce sessionId " + Hex.encodeHexString(this.getMusig2NonceSessionId()));
    }

    public boolean containsParticipantPublicKey(byte[] participantPublicKey) {
        BytesArray participantPublicKeyBytesArray = BytesArray.bytesArray(participantPublicKey);
        boolean containsParticipantPublicKey = this.getParticipantPublicKeys().contains(participantPublicKeyBytesArray);
        if (log.isDebugEnabled()) log.debug("Contains participant public key " + Hex.encodeHexString(participantPublicKeyBytesArray.bytes()) + " in " + this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList() + ": " + containsParticipantPublicKey + " (size now " + this.cohortSize() + ")");
        return containsParticipantPublicKey;
    }

    public void addParticipantPublicKey(byte[] participantPublicKey) {
        if (this.isCohortCompleted()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " already completed.");
        BytesArray participantPublicKeyBytesArray = BytesArray.bytesArray(participantPublicKey);
        if (log.isDebugEnabled()) log.debug("Adding participant public key " + Hex.encodeHexString(participantPublicKeyBytesArray.bytes()) + " to " + this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList() + " (size now " + this.cohortSize() + ")");
        this.getParticipantPublicKeys().add(participantPublicKeyBytesArray);
        if (log.isDebugEnabled()) log.debug("Added participant public key " + Hex.encodeHexString(participantPublicKeyBytesArray.bytes()) + " to " + this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList() + " (size now " + this.cohortSize() + ")");
    }

    public int findParticipantIndexByVerificationMethod(DIDDocument didDocument, URI verificationMethodId) throws RegistrationException {

        JsonLDObject verificationMethodJsonLDObject = JsonLDDereferencer.findByIdInJsonLdObject(didDocument, verificationMethodId, didDocument.getId());
        VerificationMethod verificationMethod = verificationMethodJsonLDObject == null ? null : VerificationMethod.fromJsonObject(verificationMethodJsonLDObject.getJsonObject());
        if (verificationMethod == null) throw new RegistrationException("INVALID_UPDATE", "Verification method not found: " + verificationMethodId);

        if (! "Multikey".equals(verificationMethod.getType())) {
            throw new RegistrationException("INVALID_UPDATE", "Unexpected type for '#initialKey' verification method " + verificationMethod.getId() + ": " + verificationMethod.getType());
        }

        String verificationMethodKeyString = verificationMethod.getPublicKeyMultibase();
        byte[] verificationMethodKey = verificationMethodKeyString == null ? null : MultiCodecUtil.removeMulticodec(Multibase.decode(verificationMethodKeyString), MultiCodecUtil.MULTICODEC_SECP256K1_PUB);
        if (verificationMethodKey == null) {
            throw new RegistrationException("INVALID_UPDATE", "No 'publicKeyMultibase' for '#initialKey' verification method " + verificationMethod.getId() + " and type " + verificationMethod.getType());
        }

        Integer participantIndex = null;
        for (int i=0; i<this.getParticipantPublicKeys().size(); i++) {
            BytesArray participantPublicKey = this.getParticipantPublicKeys().get(i);
            if (participantPublicKey.equals(BytesArray.bytesArray(verificationMethodKey))) {
                participantIndex = i;
                break;
            }
        }
        if (participantIndex == null) {
            throw new RegistrationException("INVALID_UPDATE", "Participant public key " + Hex.encodeHexString(verificationMethodKey) + " not found in aggregation cohort " + this.getId() + ": " + this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList());
        }

        return participantIndex;
    }

    public URI toAggregateServiceId() {
        if (! this.isCohortFinalized()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet finalized.");
        URI aggregateServiceId = URI.create("#" + this.getId());
        if (log.isDebugEnabled()) log.debug("Aggregate service ID: " + aggregateServiceId);
        return aggregateServiceId;
    }

    public String toAggregateServiceType() {
        if (! this.isCohortFinalized()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet finalized.");
        String aggregateServiceType = this.getBeaconType().getServiceType();
        if (log.isDebugEnabled()) log.debug("Aggregate service type: " + aggregateServiceType);
        return aggregateServiceType;
    }

    public URI toAggregateServiceEndpoint() {
        if (! this.isCohortFinalized()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet finalized.");
        URI aggregateServiceEndpoint = URI.create(BitcoinURI.convertToBitcoinURI(this.getBeaconAddress(), null, null, null));
        if (log.isDebugEnabled()) log.debug("Aggregate service endpoint: " + aggregateServiceEndpoint);
        return aggregateServiceEndpoint;
    }

    /*
     * Step 2: Announcing Update Opportunities
     * See https://dcdpr.github.io/did-btcr2/beacons/aggregate-beacons.html#step-2-announcing-update-opportunities
     */

    public int updatesSize() {
        return this.getUpdatesHashes().size();
    }

    public boolean isUpdatesCompleted() {
        boolean updatesCompleted = this.updatesSize() >= this.getMaxSize();
        if (log.isDebugEnabled()) log.debug("updatesCompleted? {}", updatesCompleted);
        return updatesCompleted;
    }

    public boolean isUpdatesAggregated() {
        boolean updatesAggregated = this.getUnsignedBeaconSignal() != null && this.getMusig2AggregatedNonce() != null && this.getSignalBytes() != null;
        if (log.isDebugEnabled()) log.debug("updatesAggregated? {}", updatesAggregated);
        return updatesAggregated;
    }

    public void aggregateUpdates(BitcoinConnection bitcoinConnection) throws UpdateActionFundAddressException {

        if (! this.isUpdatesCompleted()) throw new IllegalStateException("Aggregation updates " + this.getId() + " not yet completed.");
        if (this.isUpdatesAggregated()) throw new IllegalStateException("Aggregation updates " + this.getId() + " already aggregated.");

        if (this.updatesSize() != this.cohortSize()) throw new IllegalStateException("Aggregation updates number " + this.updatesSize() + " is different from " + this.cohortSize());

        if (! this.getNetwork().equals(bitcoinConnection.getNetwork())) throw new IllegalArgumentException("Invalid network: " + bitcoinConnection.getNetwork() + " is not " + this.getNetwork());

        // Aggregation of updates into a Beacon Signal depends on the type of BTCR2 Beacon.

        if (log.isDebugEnabled()) log.debug("Aggregating signal bytes for beacon type: " + this.getBeaconType());
        this.signalBytes = switch (this.getBeaconType()) {
            case CAS -> this.signalBytesCas();
            case SMT -> this.signalBytesSmt();
            default -> throw new IllegalStateException("Unexpected value: " + this.getBeaconType());
        };
        if (log.isDebugEnabled()) log.debug("Aggregated signal bytes for beacon type " + this.getBeaconType() + ": " + Hex.encodeHexString(this.getSignalBytes()));

        // it aggregates the update announcements into an Unsigned Beacon Signal.

        this.beaconAddressUtxos = bitcoinConnection.getAddressUtxos(this.getBeaconAddress().toString());
        if (log.isDebugEnabled()) log.debug("beaconAddressUtxos: {}", this.getBeaconAddressUtxos());

        Coin totalValue = Coin.valueOf(this.getBeaconAddressUtxos().stream().mapToLong(TxOut::value).sum());
        if (log.isDebugEnabled()) log.debug("totalValue: {}", totalValue);
        if (totalValue.compareTo(BITCOIN_FEE) < 0) {
            // next state
            Coin minimumValue = BITCOIN_FEE.minus(totalValue);
            throw new UpdateActionFundAddressException(this.getBeaconAddress(), minimumValue);
        }

        this.unsignedBeaconSignal = new Transaction();
        for (TxOut beaconAddressUtxo : this.getBeaconAddressUtxos()) {
            this.unsignedBeaconSignal.addInput(Sha256Hash.wrap(beaconAddressUtxo.txIdBytes()), beaconAddressUtxo.txOutIndex(), Script.parse(beaconAddressUtxo.scriptBytes()));
        }
        this.unsignedBeaconSignal.addOutput(totalValue.minus(BITCOIN_FEE), this.getBeaconAddress());
        this.unsignedBeaconSignal.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript(this.getSignalBytes()));
        if (log.isDebugEnabled()) log.debug("Unsigned beacon signal before signing: {}", this.unsignedBeaconSignal);

        // The Aggregation Service also combines the MuSig2 nonces from each Aggregation Participant following the nonce aggregation algorithm in [BIP327].

        this.musig2AggregatedNonce = IndividualNonce.aggregate(this.musig2PublicNonces.values().stream().map(BytesArray::bytes).map(IndividualNonce::new).toList()).getRight().toByteArray();

        // Once the Aggregation Participant is satisfied that the Beacon Signal only announces the BTCR2 Updates they submitted for DIDs they control,
        // they partially sign the Bitcoin transaction according to the signing algorithm specified in [BIP327].

        this.utxoAggregateSignPayloads = new TreeMap<>();
        for (int i=0; i<this.updatesSize(); i++) {
            List<BytesArray> participantUtxoAggregateSignPayloads = this.utxoAggregateSignPayloads.computeIfAbsent(i, x -> new ArrayList<>());
            for (int ii=0; ii<beaconAddressUtxos.size(); ii++) {
                Map<String, Object> participantUtxoAggregateSignPayloadMap = Map.of(
                        "tx", Base64.getEncoder().encodeToString(this.unsignedBeaconSignal.serialize()),
                        "inputIndex", ii,
                        "inputs", beaconAddressUtxos.stream().map(txOut -> new fr.acinq.bitcoin.TxOut(new Satoshi(txOut.value()), txOut.scriptBytes())).map(fr.acinq.bitcoin.TxOut::write).map(x -> Base64.getEncoder().encodeToString(x)).toList(),
                        "publicKeys", this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(x -> Base64.getEncoder().encodeToString(x)).toList(),
                        "secretNonce", Base64.getEncoder().encodeToString(this.getMusig2SecretNonces().get(i).bytes()),
                        "publicNonces", this.getMusig2PublicNonces().values().stream().map(BytesArray::bytes).map(x -> Base64.getEncoder().encodeToString(x)).toList()
                );
                String participantUtxoAggregateSignPayloadString;
                try {
                    participantUtxoAggregateSignPayloadString = jsonMapper.writeValueAsString(participantUtxoAggregateSignPayloadMap);
                } catch (JsonProcessingException ex) {
                    throw new RuntimeException(ex);
                }
                participantUtxoAggregateSignPayloads.add(BytesArray.bytesArray(participantUtxoAggregateSignPayloadString.getBytes(StandardCharsets.UTF_8)));
            }
        }
    }

    private byte[] signalBytesCas() {

        // For CAS Beacons, the Aggregation Service creates a Beacon Announcement Map that maps
        // Aggregation Participant-provided indexes to BTCR2 Update Announcements.

        if (this.updatesSize() != this.getCasDids().size()) throw new IllegalStateException("Invalid number of DIDs: " + this.getCasDids().size());
        if (this.updatesSize() != this.getCasUpdateHashes().size()) throw new IllegalStateException("Invalid number of update hashes: " + this.getCasUpdateHashes().size());

        this.casBeaconAnnouncementMap.clear();
        for (int i=0; i<this.updatesSize(); i++) {
            DID did = this.getCasDids().get(i);
            BytesArray updateHash = this.getCasUpdateHashes().get(i);
            this.casBeaconAnnouncementMap.put(did, updateHash);
        }

        // The Signal Bytes included in a CAS Beacon Signal is the SHA-256 hash of the Beacon Announcement Map.

        byte[] signalBytes = JsonCanonicalizationAndHash.jsonCanonicalizationAndHash(this.returnCasAnnouncement());
        if (log.isDebugEnabled()) log.debug("Determined signal bytes for CAS: " + Hex.encodeHexString(signalBytes));
        return signalBytes;
    }

    private byte[] signalBytesSmt() {

        // For SMT Beacons, the Aggregation Service constructs a Sparse Merkle Tree (SMT) whose leaves
        // pair each registered nonce with the value submitted for that nonce.
        // Every registered nonce MUST appear as a leaf. After constructing the SMT, the Aggregation Service
        // optimizes the tree and generates SMT Proofs for each nonce to share with the corresponding Aggregation Participant.

        if (this.updatesSize() != this.getSmtDidIndexes().size()) throw new IllegalStateException("Invalid number of DID indexes: " + this.getSmtDidIndexes().size());
        if (this.updatesSize() != this.getSmtUpdateHashes().size()) throw new IllegalStateException("Invalid number of update hashes: " + this.getSmtUpdateHashes().size());

        this.smtProofs.clear();
        SparseMerkleTree sparseMerkleTree = new SparseMerkleTree();
        for (int i=0; i<this.updatesSize(); i++) {
            BytesArray didIndex = this.getSmtDidIndexes().get(i);
            BytesArray updateHash = this.getSmtUpdateHashes().get(i);
            sparseMerkleTree.insertUpdate(didIndex.bytes(), updateHash.bytes());
            SmtProof smtProof = sparseMerkleTree.generateProofForIndex(didIndex.bytes());
            this.smtProofs.put(didIndex, smtProof);
        }

        // The Signal Bytes of an SMT Beacon Signal is the 32 byte SMT root.

        byte[] signalBytes = sparseMerkleTree.rootHash();
        if (log.isDebugEnabled()) log.debug("Determined signal bytes for SMT: " + Hex.encodeHexString(signalBytes));
        return signalBytes;
    }

    public List<BytesArray> getUpdatesHashes() {
        return switch (this.getBeaconType()) {
            case CAS -> this.getCasUpdateHashes().values().stream().toList();
            case SMT -> this.getSmtUpdateHashes().values().stream().toList();
            default -> throw new IllegalStateException("Unexpected value: " + this.getBeaconType());
        };
    }

    public CASAnnouncement returnCasAnnouncement() {
        if (! BeaconType.CAS.equals(this.getBeaconType())) return null;
        CASAnnouncement casAnnouncement = new CASAnnouncement();
        this.getCasBeaconAnnouncementMap().forEach((key, value) -> {
            casAnnouncement.put(key.getDidString(), Base64.getUrlEncoder().withoutPadding().encodeToString(value.bytes()));
        });
        return casAnnouncement;
    }

    public SmtProof returnSmtProof(DID did) {
        if (! BeaconType.SMT.equals(this.getBeaconType())) return null;
        byte[] didIndex = SHA256Util.sha256(did.getDidString().getBytes(StandardCharsets.UTF_8));
        return this.getSmtProofs().get(BytesArray.bytesArray(didIndex));
    }

    public void setCasDid(int participantIndex, DID participantCasDid) {
        this.getCasDids().put(participantIndex, participantCasDid);
    }

    public void setCasUpdateHash(int participantIndex, BytesArray participantCasUpdateHash) {
        this.getCasUpdateHashes().put(participantIndex, participantCasUpdateHash);
    }

    public void setSmtDidIndex(int participantIndex, BytesArray participantSmtDidIndex) {
        this.getSmtDidIndexes().put(participantIndex, participantSmtDidIndex);
    }

    public void setSmtUpdateHash(int participantIndex, BytesArray participantSmtUpdateHash) {
        this.getSmtUpdateHashes().put(participantIndex, participantSmtUpdateHash);
    }

    public void setMusig2SecretNonce(int participantIndex, BytesArray participantMusig2SecretNonce) {
        this.getMusig2SecretNonces().put(participantIndex, participantMusig2SecretNonce);
    }

    public void setMusig2IndividualNonce(int participantIndex, BytesArray participantMusig2IndividualNonce) {
        this.getMusig2PublicNonces().put(participantIndex, participantMusig2IndividualNonce);
    }

    /*
     * Step 3: Aggregate & Request Signal Confirmation
     * See https://dcdpr.github.io/did-btcr2/beacons/aggregate-beacons.html#step-3-aggregate--request-signal-confirmation
     */

    public int signaturesSize() {
        return this.getUtxoAggregateSignatures().size();
    }

    public boolean isSignaturesCompleted() {
        boolean signaturesCompleted = this.signaturesSize() >= this.getMaxSize();
        if (log.isDebugEnabled()) log.debug("signaturesCompleted? {}", signaturesCompleted);
        return signaturesCompleted;
    }

    public boolean isSignaturesAggregated() {
        boolean signaturesAggregated = this.getMusig2AggregatedSignatures() != null && ! this.getMusig2AggregatedSignatures().isEmpty();
        if (log.isDebugEnabled()) log.debug("signaturesAggregated? {}", signaturesAggregated);
        return signaturesAggregated;
    }

    public void aggregateSignatures(BitcoinConnection bitcoinConnection)  {

        if (! this.isSignaturesCompleted()) throw new IllegalStateException("Aggregation signatures " + this.getId() + " not yet completed.");
        if (this.isSignaturesAggregated()) throw new IllegalStateException("Aggregation signatures " + this.getId() + " already aggregated.");

        if (this.signaturesSize() != this.cohortSize()) throw new IllegalStateException("Aggregation signatures number " + this.signaturesSize() + " is different from " + this.cohortSize());

        // The Aggregation Service aggregates these partial signatures to create a final signature that spends the UTXO
        // controlled by the Beacon Address input in the Beacon Signal.

        Transaction beaconSignal = this.getUnsignedBeaconSignal();

        this.musig2AggregatedSignatures = new ArrayList<>();
        for (int i=0; i<beaconSignal.getInputs().size(); i++) {
            final int inputIndex = i;
            Either<Throwable, ByteVector64> musig2AggregatedSignature = Musig2.aggregateTaprootSignatures(
                    this.getUtxoAggregateSignatures().values().stream().map(x -> x.get(inputIndex)).map(BytesArray::bytes).map(ByteVector32::new).toList(),
                    fr.acinq.bitcoin.Transaction.read(beaconSignal.serialize()),
                    inputIndex,
                    this.getBeaconAddressUtxos().stream().map(txOut -> new fr.acinq.bitcoin.TxOut(new Satoshi(txOut.value()), txOut.scriptBytes())).toList(),
                    this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(fr.acinq.bitcoin.PublicKey::parse).toList(),
                    this.getMusig2PublicNonces().values().stream().map(BytesArray::bytes).map(IndividualNonce::new).toList(),
                    null);
            if (log.isDebugEnabled()) log.debug("Taproot session result: {}, {}, {}", musig2AggregatedSignature, musig2AggregatedSignature.getLeft(), musig2AggregatedSignature.getRight());
            if (musig2AggregatedSignature.isLeft()) throw new RuntimeException(musig2AggregatedSignature.getLeft());
            else if (musig2AggregatedSignature.isRight()) this.musig2AggregatedSignatures.add(BytesArray.bytesArray(musig2AggregatedSignature.getRight().toByteArray()));
            else throw new IllegalStateException("Invalid result: " + musig2AggregatedSignature);
        }
    }

    public void setUtxoAggregateSignatures(int participantIndex, List<BytesArray> utxoAggregateSignatures) {
        this.getUtxoAggregateSignatures().put(participantIndex, utxoAggregateSignatures);
    }

    /*
     * Step 4: Broadcast Aggregated Signal
     * See https://dcdpr.github.io/did-btcr2/beacons/aggregate-beacons.html#step-4-broadcast-aggregated-signal
     */

    public boolean isRawTransactionBroadcast() {
        return this.getBroadcastRawTransactionId() != null;
    }

    public String broadcastRawTransaction(BitcoinConnection bitcoinConnection) {

        if (this.isRawTransactionBroadcast()) throw new IllegalStateException("Raw Bitcoin transaction already broadcast.");

        // The result is a signed Bitcoin transaction.

        Transaction beaconSignal = this.getUnsignedBeaconSignal();

        for (int i=0; i<beaconSignal.getInputs().size(); i++) {
            TransactionInput transactionInput = beaconSignal.getInput(i);
            byte[] musig2AggregatedSignature = this.getMusig2AggregatedSignatures().get(i).bytes();
            TransactionWitness transactionWitness = TransactionWitness.of(musig2AggregatedSignature);
            TransactionInput signedTransactionInput = transactionInput.withWitness(transactionWitness).withoutScriptBytes();
            beaconSignal.replaceInput(i, signedTransactionInput);
        }
        if (log.isDebugEnabled()) log.debug("beaconSignal after signing: {}", beaconSignal);

        // The Aggregation Service then broadcasts this transaction onto the Bitcoin network.

        byte[] beaconSignalBytes = beaconSignal.serialize();
        if (log.isDebugEnabled()) log.debug("Broadcasting beacon signal: " + Hex.encodeHexString(beaconSignalBytes));
        this.broadcastRawTransactionId = bitcoinConnection.broadcastRawTransaction(beaconSignalBytes);
        if (log.isDebugEnabled()) log.debug("Transaction from beacon signal result: " + this.getBroadcastRawTransactionId());

        // done

        return this.getBroadcastRawTransactionId();
    }

    /*
     * Getters
     */

    public String getId() {
        return id;
    }

    public Network getNetwork() {
        return network;
    }

    public int getMaxSize() {
        return maxSize;
    }

    public BeaconType getBeaconType() {
        return beaconType;
    }

    public ScriptType getScriptType() {
        return scriptType;
    }

    public ArrayList<BytesArray> getParticipantPublicKeys() {
        return participantPublicKeys;
    }

    public Address getBeaconAddress() {
        return beaconAddress;
    }

    public byte[] getMusig2NonceSessionId() {
        return musig2NonceSessionId;
    }

    public Map<Integer, DID> getCasDids() {
        return casDids;
    }

    public Map<Integer, BytesArray> getCasUpdateHashes() {
        return casUpdateHashes;
    }

    public Map<Integer, BytesArray> getSmtDidIndexes() {
        return smtDidIndexes;
    }

    public Map<Integer, BytesArray> getSmtUpdateHashes() {
        return smtUpdateHashes;
    }

    public Map<Integer, BytesArray> getMusig2SecretNonces() {
        return musig2SecretNonces;
    }

    public Map<Integer, BytesArray> getMusig2PublicNonces() {
        return musig2PublicNonces;
    }

    public LinkedHashMap<DID, BytesArray> getCasBeaconAnnouncementMap() {
        return casBeaconAnnouncementMap;
    }

    public LinkedHashMap<BytesArray, SmtProof> getSmtProofs() {
        return smtProofs;
    }

    public Transaction getUnsignedBeaconSignal() {
        return unsignedBeaconSignal;
    }

    public byte[] getMusig2AggregatedNonce() {
        return musig2AggregatedNonce;
    }

    public byte[] getSignalBytes() {
        return signalBytes;
    }

    public List<TxOut> getBeaconAddressUtxos() {
        return beaconAddressUtxos;
    }

    public Map<Integer, List<BytesArray>> getUtxoAggregateSignPayloads() {
        return utxoAggregateSignPayloads;
    }

    public Map<Integer, List<BytesArray>> getUtxoAggregateSignatures() {
        return utxoAggregateSignatures;
    }

    public List<BytesArray> getMusig2AggregatedSignatures() {
        return musig2AggregatedSignatures;
    }

    public String getBroadcastRawTransactionId() {
        return broadcastRawTransactionId;
    }

    /*
     * Object methods
     */

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        AggregationCohort that = (AggregationCohort) o;
        return maxSize == that.maxSize && Objects.equals(id, that.id) && network == that.network && beaconType == that.beaconType && scriptType == that.scriptType && Objects.equals(participantPublicKeys, that.participantPublicKeys) && Objects.equals(beaconAddress, that.beaconAddress) && Objects.deepEquals(musig2NonceSessionId, that.musig2NonceSessionId) && Objects.equals(casDids, that.casDids) && Objects.equals(casUpdateHashes, that.casUpdateHashes) && Objects.equals(smtDidIndexes, that.smtDidIndexes) && Objects.equals(smtUpdateHashes, that.smtUpdateHashes) && Objects.equals(musig2SecretNonces, that.musig2SecretNonces) && Objects.equals(musig2PublicNonces, that.musig2PublicNonces) && Objects.equals(casBeaconAnnouncementMap, that.casBeaconAnnouncementMap) && Objects.equals(smtProofs, that.smtProofs) && Objects.equals(unsignedBeaconSignal, that.unsignedBeaconSignal) && Objects.deepEquals(musig2AggregatedNonce, that.musig2AggregatedNonce) && Objects.deepEquals(signalBytes, that.signalBytes) && Objects.equals(beaconAddressUtxos, that.beaconAddressUtxos) && Objects.equals(utxoAggregateSignPayloads, that.utxoAggregateSignPayloads) && Objects.equals(utxoAggregateSignatures, that.utxoAggregateSignatures) && Objects.equals(musig2AggregatedSignatures, that.musig2AggregatedSignatures) && Objects.equals(broadcastRawTransactionId, that.broadcastRawTransactionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, network, maxSize, beaconType, scriptType, participantPublicKeys, beaconAddress, Arrays.hashCode(musig2NonceSessionId), casDids, casUpdateHashes, smtDidIndexes, smtUpdateHashes, musig2SecretNonces, musig2PublicNonces, casBeaconAnnouncementMap, smtProofs, unsignedBeaconSignal, Arrays.hashCode(musig2AggregatedNonce), Arrays.hashCode(signalBytes), beaconAddressUtxos, utxoAggregateSignPayloads, utxoAggregateSignatures, musig2AggregatedSignatures, broadcastRawTransactionId);
    }

    @Override
    public String toString() {
        return "AggregationCohort{" +
                "id='" + id + '\'' +
                ", network=" + network +
                ", maxSize=" + maxSize +
                ", beaconType=" + beaconType +
                ", scriptType=" + scriptType +
                ", participantPublicKeys=" + participantPublicKeys +
                ", beaconAddress=" + beaconAddress +
                ", musig2NonceSessionId=" + Arrays.toString(musig2NonceSessionId) +
                ", casDids=" + casDids +
                ", casUpdateHashes=" + casUpdateHashes +
                ", smtDidIndexes=" + smtDidIndexes +
                ", smtUpdateHashes=" + smtUpdateHashes +
                ", musig2SecretNonces=" + musig2SecretNonces +
                ", musig2PublicNonces=" + musig2PublicNonces +
                ", casBeaconAnnouncementMap=" + casBeaconAnnouncementMap +
                ", smtProofs=" + smtProofs +
                ", unsignedBeaconSignal=" + unsignedBeaconSignal +
                ", musig2AggregatedNonce=" + Arrays.toString(musig2AggregatedNonce) +
                ", signalBytes=" + Arrays.toString(signalBytes) +
                ", beaconAddressUtxos=" + beaconAddressUtxos +
                ", utxoAggregateSignPayloads=" + utxoAggregateSignPayloads +
                ", utxoAggregateSignatures=" + utxoAggregateSignatures +
                ", musig2AggregatedSignatures=" + musig2AggregatedSignatures +
                ", broadcastRawTransactionId='" + broadcastRawTransactionId + '\'' +
                '}';
    }
}
