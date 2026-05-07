package uniregistrar.driver.did.btcr2.aggregation;

import com.danubetech.btc.connection.BitcoinConnector;
import com.danubetech.btc.connection.Network;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDDereferencer;
import foundation.identity.jsonld.JsonLDObject;
import fr.acinq.bitcoin.BlockHash;
import fr.acinq.bitcoin.Crypto;
import fr.acinq.bitcoin.PublicKey;
import fr.acinq.bitcoin.XonlyPublicKey;
import fr.acinq.bitcoin.crypto.musig2.Musig2;
import io.ipfs.multibase.Multibase;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.AddressParser;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.uri.BitcoinURI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scala.util.control.Exception;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.beacons.BeaconType;
import uniregistrar.driver.did.btcr2.data.json.SMTProof;
import uniregistrar.driver.did.btcr2.util.BytesUtil;
import uniregistrar.driver.did.btcr2.util.MultiCodecUtil;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.*;

public class AggregationCohort {

    private static final Logger log = LoggerFactory.getLogger(AggregationCohort.class);

    public static final int SCHNORR_PUBLIC_KEY_SIZE = 32;

    private final String id;
    private final Network network;
    private final int maxSize;
    private final BeaconType beaconType;
    private final ScriptType scriptType;

    private ArrayList<ByteBuffer> participantPublicKeys = new ArrayList<>();
    private Address beaconAddress;

    // For a CAS Beacon:

    private ArrayList<DID> casDids = new ArrayList<>();
    private ArrayList<ByteBuffer> casUpdateHashes = new ArrayList<>();

    // For an SMT Beacon:

    private ArrayList<ByteBuffer> smtDidIndexes = new ArrayList<>();
    private ArrayList<ByteBuffer> smtUpdateHashes = new ArrayList<>();
    private ArrayList<ByteBuffer> smtNonces = new ArrayList<>();

    // For a CAS Beacon:
    // For an SMT Beacon:

    private ArrayList<ByteBuffer> musig2SecretNonces = new ArrayList<>();
    private ArrayList<ByteBuffer> musig2IndividualNonces = new ArrayList<>();

    // For a CAS Beacon, the request signal confirmation message contains:

    private LinkedHashMap<DID, byte[]> casBeaconAnnouncementMap = new LinkedHashMap<>();

    // For an SMT Beacon, the request signal confirmation message contains:

    private LinkedHashMap<ByteBuffer, SMTProof> smtProof = new LinkedHashMap<>();

    // For a CAS Beacon, the request signal confirmation message contains:
    // For an SMT Beacon, the request signal confirmation message contains:

    private byte[] unsignedBeaconSignal;
    private String musig2AggregatedNonce;

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

    public boolean containsParticipantPublicKey(byte[] participantPublicKey) {
        ByteBuffer participantPublicKeyByteBuffer = BytesUtil.byteBuffer(participantPublicKey);
        boolean containsParticipantPublicKey = this.getParticipantPublicKeys().contains(participantPublicKeyByteBuffer);
        if (log.isDebugEnabled()) log.debug("Contains participant public key " + Hex.encodeHexString(participantPublicKeyByteBuffer.duplicate()) + " in " + this.getParticipantPublicKeys().stream().map(ByteBuffer::duplicate).map(Hex::encodeHexString).toList() + ": " + containsParticipantPublicKey + " (size now " + this.cohortSize() + ")");
        return containsParticipantPublicKey;
    }

    public void addParticipantPublicKey(byte[] participantPublicKey) {
        if (isCohortCompleted()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " already completed.");
        ByteBuffer participantPublicKeyByteBuffer = BytesUtil.byteBuffer(participantPublicKey);
        if (log.isDebugEnabled()) log.debug("Adding participant public key " + Hex.encodeHexString(participantPublicKeyByteBuffer.duplicate()) + " to " + this.getParticipantPublicKeys().stream().map(ByteBuffer::duplicate).map(Hex::encodeHexString).toList() + " (size now " + this.cohortSize() + ")");
        this.getParticipantPublicKeys().add(participantPublicKeyByteBuffer);
        if (log.isDebugEnabled()) log.debug("Added participant public key " + Hex.encodeHexString(participantPublicKeyByteBuffer.duplicate()) + " to " + this.getParticipantPublicKeys().stream().map(ByteBuffer::duplicate).map(Hex::encodeHexString).toList() + " (size now " + this.cohortSize() + ")");
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
            ByteBuffer participantPublicKey = this.getParticipantPublicKeys().get(i);
            if (participantPublicKey.equals(BytesUtil.byteBuffer(verificationMethodKey))) {
                participantIndex = i;
                break;
            }
        }
        if (participantIndex == null) {
            throw new RegistrationException("INVALID_UPDATE", "Participant public key " + Hex.encodeHexString(verificationMethodKey) + " not found in aggregation cohort " + this.getId() + ": " + this.getParticipantPublicKeys().stream().map(Hex::encodeHexString).toList());
        }

        return participantIndex;
    }

    public void finalizeCohort(BitcoinConnector bitcoinConnector) {

        if (! isCohortCompleted()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet completed.");
        if (isCohortFinalized()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " already finalized.");

        this.beaconAddress = switch (this.getScriptType()) {
            case P2SH -> {
                List<ECKey> publicKeys = new ArrayList<>(this.getParticipantPublicKeys().stream().map(ByteBuffer::duplicate).map(ByteBuffer::array).map(ECKey::fromPublicOnly).toList());
                publicKeys.sort(ECKey.PUBKEY_COMPARATOR);
                Script script = ScriptBuilder.createRedeemScript(this.getParticipantPublicKeys().size(), publicKeys);
                yield LegacyAddress.fromScriptHash(this.getNetwork().toBitcoinjNetwork(), ScriptPattern.extractHashFromP2SH(script));
            }
            case P2WSH -> {
                List<ECKey> publicKeys = new ArrayList<>(this.getParticipantPublicKeys().stream().map(ByteBuffer::duplicate).map(ByteBuffer::array).map(ECKey::fromPublicOnly).toList());
                publicKeys.sort(ECKey.PUBKEY_COMPARATOR);
                Script script = ScriptBuilder.createRedeemScript(this.getParticipantPublicKeys().size(), publicKeys);
                yield LegacyAddress.fromScriptHash(this.getNetwork().toBitcoinjNetwork(), ScriptPattern.extractHashFromP2PKH(script));
            }
            case P2TR -> {
                List<PublicKey> publicKeys = this.getParticipantPublicKeys().stream().map(ByteBuffer::duplicate).map(ByteBuffer::array).map(PublicKey::parse).toList();
                XonlyPublicKey aggregatePublicKey = Musig2.aggregateKeys(publicKeys);
                aggregatePublicKey.tweak(Crypto.TaprootTweak.KeyPathTweak.INSTANCE);
                yield AddressParser.getDefault().parseAddress(aggregatePublicKey.p2trAddress(new BlockHash(bitcoinConnector.getGensisHash(this.getNetwork()))));
            }
            default -> throw new IllegalStateException("Invalid script type, not aupported for aggregation cohort: " + this.getScriptType());
        };

        if (log.isDebugEnabled()) log.debug("For script tyoe " + this.getScriptType() + " and size " + this.cohortSize() + " finalized cohort with beacon address: " + this.getBeaconAddress());
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
        return this.getParticipantPublicKeys().size();
    }

    public boolean isUpdatesCompleted() {
        return this.cohortSize() >= this.getMaxSize();
    }

    public boolean isUpdatesFinalized() {
        return this.getBeaconAddress() != null;
    }

    public void setCasDid(int participantIndex, DID participantCasDid) {
        this.getCasDids().set(participantIndex, participantCasDid);
    }

    public void setCasUpdateHash(int participantIndex, ByteBuffer participantCasUpdateHash) {
        this.getCasUpdateHashes().set(participantIndex, participantCasUpdateHash);
    }

    public void setSmtDidIndex(int participantIndex, ByteBuffer participantSmtDidIndex) {
        this.getSmtDidIndexes().set(participantIndex, participantSmtDidIndex);
    }

    public void setSmtUpdateHash(int participantIndex, ByteBuffer participantSmtUpdateHash) {
        this.getSmtUpdateHashes().set(participantIndex, participantSmtUpdateHash);
    }

    public void setSmtNonce(int participantIndex, ByteBuffer participantSmtNonce) {
        this.getSmtNonces().set(participantIndex, participantSmtNonce);
    }

    public void setMusig2SecretNonce(int participantIndex, ByteBuffer participantMusig2SecretNonce) {
        this.getMusig2SecretNonces().set(participantIndex, participantMusig2SecretNonce);
    }

    public void setMusig2IndividualNonce(int participantIndex, ByteBuffer participantMusig2IndividualNonce) {
        this.getMusig2IndividualNonces().set(participantIndex, participantMusig2IndividualNonce);
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

    public ArrayList<ByteBuffer> getParticipantPublicKeys() {
        return participantPublicKeys;
    }

    public Address getBeaconAddress() {
        return beaconAddress;
    }

    public ArrayList<DID> getCasDids() {
        return casDids;
    }

    public ArrayList<ByteBuffer> getCasUpdateHashes() {
        return casUpdateHashes;
    }

    public ArrayList<ByteBuffer> getSmtDidIndexes() {
        return smtDidIndexes;
    }

    public ArrayList<ByteBuffer> getSmtUpdateHashes() {
        return smtUpdateHashes;
    }

    public ArrayList<ByteBuffer> getSmtNonces() {
        return smtNonces;
    }

    public ArrayList<ByteBuffer> getMusig2SecretNonces() {
        return musig2SecretNonces;
    }

    public ArrayList<ByteBuffer> getMusig2IndividualNonces() {
        return musig2IndividualNonces;
    }

    public LinkedHashMap<DID, byte[]> getCasBeaconAnnouncementMap() {
        return casBeaconAnnouncementMap;
    }

    public LinkedHashMap<ByteBuffer, SMTProof> getSmtProof() {
        return smtProof;
    }

    public byte[] getUnsignedBeaconSignal() {
        return unsignedBeaconSignal;
    }

    public String getMusig2AggregatedNonce() {
        return musig2AggregatedNonce;
    }

    /*
     * Object methods
     */

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        AggregationCohort that = (AggregationCohort) o;
        return maxSize == that.maxSize && Objects.equals(id, that.id) && network == that.network && beaconType == that.beaconType && scriptType == that.scriptType && Objects.equals(participantPublicKeys, that.participantPublicKeys) && Objects.equals(beaconAddress, that.beaconAddress) && Objects.equals(casDids, that.casDids) && Objects.equals(casUpdateHashes, that.casUpdateHashes) && Objects.equals(smtDidIndexes, that.smtDidIndexes) && Objects.equals(smtUpdateHashes, that.smtUpdateHashes) && Objects.equals(smtNonces, that.smtNonces) && Objects.equals(musig2SecretNonces, that.musig2SecretNonces) && Objects.equals(musig2IndividualNonces, that.musig2IndividualNonces) && Objects.equals(casBeaconAnnouncementMap, that.casBeaconAnnouncementMap) && Objects.equals(smtProof, that.smtProof) && Objects.deepEquals(unsignedBeaconSignal, that.unsignedBeaconSignal) && Objects.equals(musig2AggregatedNonce, that.musig2AggregatedNonce);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, network, maxSize, beaconType, scriptType, participantPublicKeys, beaconAddress, casDids, casUpdateHashes, smtDidIndexes, smtUpdateHashes, smtNonces, musig2SecretNonces, musig2IndividualNonces, casBeaconAnnouncementMap, smtProof, Arrays.hashCode(unsignedBeaconSignal), musig2AggregatedNonce);
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
                ", smtProof=" + smtProof +
                ", unsignedBeaconSignal=" + Arrays.toString(unsignedBeaconSignal) +
                ", musig2AggregatedNonce='" + musig2AggregatedNonce + '\'' +
                '}';
    }
}
