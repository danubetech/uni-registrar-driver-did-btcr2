package uniregistrar.driver.did.btcr2.aggregation;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.BitcoinConnector;
import com.danubetech.btc.connection.Network;
import com.danubetech.btc.connection.records.TxOut;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDDereferencer;
import foundation.identity.jsonld.JsonLDObject;
import fr.acinq.bitcoin.BlockHash;
import fr.acinq.bitcoin.Crypto;
import fr.acinq.bitcoin.PublicKey;
import fr.acinq.bitcoin.XonlyPublicKey;
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce;
import fr.acinq.bitcoin.crypto.musig2.Musig2;
import fr.acinq.bitcoin.crypto.musig2.Session;
import fr.acinq.bitcoin.utils.Either;
import io.ipfs.multibase.Multibase;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.*;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
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
import uniregistrar.driver.did.btcr2.data.json.SMTProof;
import uniregistrar.driver.did.btcr2.util.BytesArray;
import uniregistrar.driver.did.btcr2.util.MultiCodecUtil;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class AggregationCohort {

    private static final Logger log = LoggerFactory.getLogger(AggregationCohort.class);

    private static final Coin BITCOIN_FEE = Coin.valueOf(100);
    private static final int SCHNORR_PUBLIC_KEY_SIZE = 32;

    private final String id;
    private final Network network;
    private final int maxSize;
    private final BeaconType beaconType;
    private final ScriptType scriptType;

    private ArrayList<BytesArray> participantPublicKeys = new ArrayList<>();
    private Address beaconAddress;

    // For a CAS Beacon:

    private Map<Integer, DID> casDids = new TreeMap<>();
    private Map<Integer, BytesArray> casUpdateHashes = new TreeMap<>();

    // For an SMT Beacon:

    private Map<Integer, BytesArray> smtDidIndexes = new TreeMap<>();
    private Map<Integer, BytesArray> smtUpdateHashes = new TreeMap<>();
    private Map<Integer, BytesArray> smtNonces = new TreeMap<>();

    // For a CAS Beacon:
    // For an SMT Beacon:

    private Map<Integer, BytesArray> musig2SecretNonces = new TreeMap<>();
    private Map<Integer, BytesArray> musig2IndividualNonces = new TreeMap<>();

    // For a CAS Beacon, the request signal confirmation message contains:

    private LinkedHashMap<DID, BytesArray> casBeaconAnnouncementMap = new LinkedHashMap<>();

    // For an SMT Beacon, the request signal confirmation message contains:

    private LinkedHashMap<BytesArray, SMTProof> smtProofs = new LinkedHashMap<>();

    // For a CAS Beacon, the request signal confirmation message contains:
    // For an SMT Beacon, the request signal confirmation message contains:

    private byte[] signalBytes;
    private Transaction unsignedBeaconSignal;
    private List<byte[]> utxoAggregateSignPayloads;
    private byte[] musig2AggregatedNonce;

    public AggregationCohort(String id, Network network, int maxSize, BeaconType beaconType, ScriptType scriptType) {
        this.id = id;
        this.network = network;
        this.maxSize = maxSize;
        this.beaconType = beaconType;
        this.scriptType = scriptType;
    }

    /*
     * Step 1: Create Aggregation Cohort
     * See https://dcdpr.github.io/did-btcr2/beacons/aggregate-beacons.html#step-1-create-aggregation-cohort
     */

    public int cohortSize() {
        return this.getParticipantPublicKeys().size();
    }

    public boolean isCohortCompleted() {
        return this.cohortSize() >= this.getMaxSize();
    }

    public boolean isCohortFinalized() {
        return this.getBeaconAddress() != null;
    }

    public void finalizeCohort(BitcoinConnector bitcoinConnector) {

        if (! isCohortCompleted()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet completed.");
        if (isCohortFinalized()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " already finalized.");

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

        if (log.isDebugEnabled()) log.debug("For script tyoe " + this.getScriptType() + " and size " + this.cohortSize() + " finalized cohort with beacon address: " + this.getBeaconAddress());
    }

    public boolean containsParticipantPublicKey(byte[] participantPublicKey) {
        BytesArray participantPublicKeyBytesArray = BytesArray.bytesArray(participantPublicKey);
        boolean containsParticipantPublicKey = this.getParticipantPublicKeys().contains(participantPublicKeyBytesArray);
        if (log.isDebugEnabled()) log.debug("Contains participant public key " + Hex.encodeHexString(participantPublicKeyBytesArray.bytes()) + " in " + this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList() + ": " + containsParticipantPublicKey + " (size now " + this.cohortSize() + ")");
        return containsParticipantPublicKey;
    }

    public void addParticipantPublicKey(byte[] participantPublicKey) {
        if (isCohortCompleted()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " already completed.");
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
        if (! isCohortFinalized()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet finalized.");
        URI aggregateServiceId = URI.create("#" + this.getId());
        if (log.isDebugEnabled()) log.debug("Aggregate service ID: " + aggregateServiceId);
        return aggregateServiceId;
    }

    public String toAggregateServiceType() {
        if (! isCohortFinalized()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet finalized.");
        String aggregateServiceType = this.getBeaconType().getServiceType();
        if (log.isDebugEnabled()) log.debug("Aggregate service type: " + aggregateServiceType);
        return aggregateServiceType;
    }

    public URI toAggregateServiceEndpoint() {
        if (! isCohortFinalized()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet finalized.");
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
        return this.updatesSize() >= this.getMaxSize();
    }

    public boolean isUpdatesAggregated() {
        return this.getSignalBytes() != null && this.getUnsignedBeaconSignal() != null && this.getMusig2AggregatedNonce() != null;
    }

    public void aggregateUpdates(BitcoinConnection bitcoinConnection) throws UpdateActionFundAddressException {

        if (! isUpdatesCompleted()) throw new IllegalStateException("Aggregation updates " + this.getId() + " not yet completed.");
        if (isUpdatesAggregated()) throw new IllegalStateException("Aggregation updates " + this.getId() + " already aggregated.");

        if (! this.getNetwork().equals(bitcoinConnection.getNetwork())) throw new IllegalArgumentException("Invalid network: " + bitcoinConnection.getNetwork() + " is not " + this.getNetwork());

        switch (this.getBeaconType()) {
            case CAS -> this.aggregateUpdatesCas();
            case SMT -> this.aggregateUpdatesSmt();
            default -> throw new IllegalStateException("Unexpected value: " + this.getBeaconType());
        };

        // The Unsigned Beacon Signal.

        List<TxOut> beaconAddressUtxos = bitcoinConnection.getAddressUtxos(this.getBeaconAddress().toString());
        if (log.isDebugEnabled()) log.debug("beaconAddressUtxos: {}", beaconAddressUtxos);

        Coin totalValue = Coin.valueOf(beaconAddressUtxos.stream().mapToLong(TxOut::value).sum());
        if (log.isDebugEnabled()) log.debug("totalValue: {}", totalValue);
        if (totalValue.compareTo(BITCOIN_FEE) < 0) {
            // next state
            Coin minimumValue = BITCOIN_FEE.minus(totalValue);
            throw new UpdateActionFundAddressException(this.getBeaconAddress(), minimumValue);
        }

        this.unsignedBeaconSignal = new Transaction();
        for (TxOut beaconAddressUtxo : beaconAddressUtxos) {
            this.unsignedBeaconSignal.addInput(Sha256Hash.wrap(beaconAddressUtxo.txIdBytes()), beaconAddressUtxo.txOutIndex(), Script.parse(beaconAddressUtxo.scriptBytes()));
        }
        this.unsignedBeaconSignal.addOutput(totalValue.minus(BITCOIN_FEE), this.getBeaconAddress());
        this.unsignedBeaconSignal.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript(this.getSignalBytes()));
        if (log.isDebugEnabled()) log.debug("Unsigned beacon signal before signing: {}", this.unsignedBeaconSignal);

        // Aggregation Participants return the partially signed Bitcoin transaction to the Aggregation Service

        this.utxoAggregateSignPayloads = IntStream.range(0, this.unsignedBeaconSignal.getInputs().size())
                .mapToObj(i -> {
                    Either<Throwable, Session> either = Musig2.taprootSession(
                            fr.acinq.bitcoin.Transaction.read(this.unsignedBeaconSignal.serialize()),
                            i,
                            this.unsignedBeaconSignal.getInputs().stream().map(TransactionInput::getConnectedOutput).map(TransactionOutput::serialize).map(fr.acinq.bitcoin.TxOut::read).toList(),
                            this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(fr.acinq.bitcoin.PublicKey::parse).toList(),
                            this.getMusig2IndividualNonces().values().stream().map(BytesArray::bytes).map(IndividualNonce::new).toList(),
                            null);
                    if (either.isLeft()) throw new RuntimeException(either.getLeft());
                    Session session = either.getRight();
                    return session.toByteArray();
                })
                .toList();

        // The MuSig2 aggregated nonce.

        this.musig2AggregatedNonce = IndividualNonce.aggregate(this.musig2IndividualNonces.values().stream().map(BytesArray::bytes).map(IndividualNonce::new).toList()).getRight().toByteArray();
    }

    private void aggregateUpdatesCas() {

        // For CAS Beacons, the Aggregation Service creates a Beacon Announcement Map that maps
        // Aggregation Participant-provided indexes to BTCR2 Update Announcements.

        if (this.updatesSize() != this.getCasDids().size()) throw new IllegalStateException("Invalid number of DIDs: " + this.getCasDids().size());
        if (this.updatesSize() != this.getCasUpdateHashes().size()) throw new IllegalStateException("Invalid number of update hashes: " + this.getCasUpdateHashes().size());

        this.casBeaconAnnouncementMap.clear();
        for (int i=0; i<this.updatesSize(); i++) {
            this.casBeaconAnnouncementMap.put(this.getCasDids().get(i), this.getCasUpdateHashes().get(i));
        }

        // The Signal Bytes included in a CAS Beacon Signal is the SHA-256 hash of the Beacon Announcement Map.

        this.signalBytes = JsonCanonicalizationAndHash.jsonCanonicalizationAndHash(this.casBeaconAnnouncementMap
                .entrySet()
                .stream()
                .collect(
                        Collectors.toMap(
                                x -> x.getKey().toString(),
                                x -> Base64.getUrlEncoder().withoutPadding().encodeToString(x.getValue().bytes()))));
    }

    private void aggregateUpdatesSmt() {

        // For SMT Beacons, the Aggregation Service constructs a Sparse Merkle Tree (SMT) whose leaves
        // pair each registered index with the value submitted for that index.
        // Every registered index MUST appear as a leaf. After constructing the SMT, the Aggregation Service
        // optimizes the tree and generates SMT Proofs for each index to share with the corresponding Aggregation Participant.

        if (this.updatesSize() != this.getSmtDidIndexes().size()) throw new IllegalStateException("Invalid number of DID indexes: " + this.getSmtDidIndexes().size());
        if (this.updatesSize() != this.getSmtUpdateHashes().size()) throw new IllegalStateException("Invalid number of update hashes: " + this.getSmtUpdateHashes().size());
        if (this.updatesSize() != this.getSmtNonces().size()) throw new IllegalStateException("Invalid number of nonces: " + this.getSmtNonces().size());

        this.smtProofs.clear();
        for (int i=0; i<this.updatesSize(); i++) {
            SMTProof smtProof = new SMTProof(); /* TODO */
            this.smtProofs.put(this.getSmtDidIndexes().get(i), smtProof);
        }

        // The Signal Bytes of an SMT Beacon Signal is the 32 byte SMT root.

        this.signalBytes = new byte[32]; /* TODO */
    }

    public List<BytesArray> getUpdatesHashes() {
        return switch (this.getBeaconType()) {
            case CAS -> this.getCasUpdateHashes().values().stream().toList();
            case SMT -> this.getSmtUpdateHashes().values().stream().toList();
            default -> throw new IllegalStateException("Unexpected value: " + this.getBeaconType());
        };
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

    public void setSmtNonce(int participantIndex, BytesArray participantSmtNonce) {
        this.getSmtNonces().put(participantIndex, participantSmtNonce);
    }

    public void setMusig2SecretNonce(int participantIndex, BytesArray participantMusig2SecretNonce) {
        this.getMusig2SecretNonces().put(participantIndex, participantMusig2SecretNonce);
    }

    public void setMusig2IndividualNonce(int participantIndex, BytesArray participantMusig2IndividualNonce) {
        this.getMusig2IndividualNonces().put(participantIndex, participantMusig2IndividualNonce);
    }

    public Map<String, Object> getMetadata() {

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("id", this.getId());
        metadata.put("network", this.getNetwork().toString());
        metadata.put("beaconType", this.getBeaconType().toString());
        metadata.put("scriptType", this.getScriptType().toString());
        metadata.put("cohortSize", this.cohortSize());
        metadata.put("updatesSize", this.updatesSize());
        metadata.put("maxSize", this.getMaxSize());
        metadata.put("participantPublicKeys", this.getParticipantPublicKeys().stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList());
        metadata.put("updateHashes", this.getUpdatesHashes().stream().map(BytesArray::bytes).map(Hex::encodeHexString).toList());
        metadata.put("isCohortCompleted", this.isCohortCompleted());
        metadata.put("isCohortFinalized", this.isCohortFinalized());
        metadata.put("isUpdatesCompleted", this.isUpdatesCompleted());
        metadata.put("isUpdatesFinalized", this.isUpdatesAggregated());
        metadata.put("beaconAddress", this.getBeaconAddress() == null ? null : this.getBeaconAddress().toString());
        metadata.put("signalBytes", this.getSignalBytes() == null ? null : Hex.encodeHexString(this.getSignalBytes()));
        metadata.put("unsignedBeaconSignal", this.getUnsignedBeaconSignal() == null ? null : Hex.encodeHexString(this.getUnsignedBeaconSignal().serialize()));
        metadata.put("musig2AggregatedNonce", this.getMusig2AggregatedNonce() == null ? null : Hex.encodeHexString(this.getMusig2AggregatedNonce()));
        return Map.of("aggregationCohort", metadata);
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

    public Map<Integer, BytesArray> getSmtNonces() {
        return smtNonces;
    }

    public Map<Integer, BytesArray> getMusig2SecretNonces() {
        return musig2SecretNonces;
    }

    public Map<Integer, BytesArray> getMusig2IndividualNonces() {
        return musig2IndividualNonces;
    }

    public LinkedHashMap<DID, BytesArray> getCasBeaconAnnouncementMap() {
        return casBeaconAnnouncementMap;
    }

    public LinkedHashMap<BytesArray, SMTProof> getSmtProofs() {
        return smtProofs;
    }

    public byte[] getSignalBytes() {
        return signalBytes;
    }

    public Transaction getUnsignedBeaconSignal() {
        return unsignedBeaconSignal;
    }

    public List<byte[]> getUtxoAggregateSignPayloads() {
        return utxoAggregateSignPayloads;
    }

    public byte[] getMusig2AggregatedNonce() {
        return musig2AggregatedNonce;
    }

    /*
     * Object methods
     */

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        AggregationCohort that = (AggregationCohort) o;
        return maxSize == that.maxSize && Objects.equals(id, that.id) && network == that.network && beaconType == that.beaconType && scriptType == that.scriptType && Objects.equals(participantPublicKeys, that.participantPublicKeys) && Objects.equals(beaconAddress, that.beaconAddress) && Objects.equals(casDids, that.casDids) && Objects.equals(casUpdateHashes, that.casUpdateHashes) && Objects.equals(smtDidIndexes, that.smtDidIndexes) && Objects.equals(smtUpdateHashes, that.smtUpdateHashes) && Objects.equals(smtNonces, that.smtNonces) && Objects.equals(musig2SecretNonces, that.musig2SecretNonces) && Objects.equals(musig2IndividualNonces, that.musig2IndividualNonces) && Objects.equals(casBeaconAnnouncementMap, that.casBeaconAnnouncementMap) && Objects.equals(smtProofs, that.smtProofs) && Objects.deepEquals(signalBytes, that.signalBytes) && Objects.equals(unsignedBeaconSignal, that.unsignedBeaconSignal) && Objects.equals(utxoAggregateSignPayloads, that.utxoAggregateSignPayloads) && Objects.deepEquals(musig2AggregatedNonce, that.musig2AggregatedNonce);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, network, maxSize, beaconType, scriptType, participantPublicKeys, beaconAddress, casDids, casUpdateHashes, smtDidIndexes, smtUpdateHashes, smtNonces, musig2SecretNonces, musig2IndividualNonces, casBeaconAnnouncementMap, smtProofs, Arrays.hashCode(signalBytes), unsignedBeaconSignal, utxoAggregateSignPayloads, Arrays.hashCode(musig2AggregatedNonce));
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
                ", casDids=" + casDids +
                ", casUpdateHashes=" + casUpdateHashes +
                ", smtDidIndexes=" + smtDidIndexes +
                ", smtUpdateHashes=" + smtUpdateHashes +
                ", smtNonces=" + smtNonces +
                ", musig2SecretNonces=" + musig2SecretNonces +
                ", musig2IndividualNonces=" + musig2IndividualNonces +
                ", casBeaconAnnouncementMap=" + casBeaconAnnouncementMap +
                ", smtProofs=" + smtProofs +
                ", signalBytes=" + Arrays.toString(signalBytes) +
                ", unsignedBeaconSignal=" + unsignedBeaconSignal +
                ", utxoSingletonSignPayloads=" + utxoAggregateSignPayloads +
                ", musig2AggregatedNonce=" + Arrays.toString(musig2AggregatedNonce) +
                '}';
    }
}
