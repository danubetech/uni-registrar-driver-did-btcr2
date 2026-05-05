package uniregistrar.driver.did.btcr2.aggregation;

import com.danubetech.btc.connection.BitcoinConnector;
import com.danubetech.btc.connection.Network;
import foundation.identity.did.DID;
import fr.acinq.bitcoin.BlockHash;
import fr.acinq.bitcoin.Crypto;
import fr.acinq.bitcoin.PublicKey;
import fr.acinq.bitcoin.XonlyPublicKey;
import fr.acinq.bitcoin.crypto.musig2.Musig2;
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
import uniregistrar.driver.did.btcr2.beacons.BeaconType;
import uniregistrar.driver.did.btcr2.data.json.SMTProof;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AggregationCohort {

        private static final Logger log = LoggerFactory.getLogger(AggregationCohort.class);

        public static final int SCHNORR_PUBLIC_KEY_SIZE = 32;

        private final String id;
        private final Network network;
        private final int maxSize;
        private final BeaconType beaconType;
        private final ScriptType scriptType;

        public AggregationCohort(String id, Network network, int maxSize, BeaconType beaconType, ScriptType scriptType) {
                this.id = id;
                this.network = network;
                this.maxSize = maxSize;
                this.beaconType = beaconType;
                this.scriptType = scriptType;
        }

        private List<byte[]> participantPublicKeys = new ArrayList<>();
        private Address beaconAddress;

        // For a CAS Beacon:

        private Map<DID, byte[]> casUpdateHashes = new HashMap<>();

        // For an SMT Beacon:

        private Map<byte[], byte[]> smtUpdateHashes = new HashMap<>();
        private Map<byte[], String> smtNonces = new HashMap<>();

        // For a CAS Beacon:
        // For an SMT Beacon:

        private List<String> musig2Nonces = new ArrayList<>();

        // For a CAS Beacon, the request signal confirmation message contains:

        private Map<DID, byte[]> beaconAnnouncementMap = new HashMap<>();

        // For an SMT Beacon, the request signal confirmation message contains:

        private Map<byte[], SMTProof> smtProof = new HashMap<>();

        // For a CAS Beacon, the request signal confirmation message contains:
        // For an SMT Beacon, the request signal confirmation message contains:

        private byte[] unsignedBeaconSignal;
        private String musig2AggregatedNonce;

        public int size() {
                return this.getParticipantPublicKeys().size();
        }

        public boolean containsParticipantPublicKey(byte[] participantPublicKey) {
                boolean containsParticipantPublicKey = this.getParticipantPublicKeys().contains(participantPublicKey);
                if (log.isDebugEnabled()) log.debug("Contains participant public key " + Hex.encodeHexString(participantPublicKey) + " in " + this.getParticipantPublicKeys().stream().map(Hex::encodeHexString).toList() + ": " + containsParticipantPublicKey);
                return containsParticipantPublicKey;
        }

        public void addParticipantPublicKey(byte[] participantPublicKey) {
                if (isCompletedCohort()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " already completed.");
                this.getParticipantPublicKeys().add(participantPublicKey);
                if (log.isDebugEnabled()) log.debug("Added participant public key: " + Hex.encodeHexString(participantPublicKey) + " (size now " + this.size() + ")");
        }

        public boolean isCompletedCohort() {
                return this.size() >= this.getMaxSize();
        }

        public void finalizeCohort(BitcoinConnector bitcoinConnector) {
                if (isFinalizedCohort()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " already finalized.");
                if (! isCompletedCohort()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet completed.");
                this.beaconAddress = switch (this.getScriptType()) {
                        case P2SH -> {
                                List<ECKey> publicKeys = new ArrayList<>(this.getParticipantPublicKeys().stream().map(ECKey::fromPublicOnly).toList());
                                publicKeys.sort(ECKey.PUBKEY_COMPARATOR);
                                Script script = ScriptBuilder.createRedeemScript(this.getParticipantPublicKeys().size(), publicKeys);
                                yield LegacyAddress.fromScriptHash(this.getNetwork().toBitcoinjNetwork(), ScriptPattern.extractHashFromP2SH(script));
                        }
                        case P2WSH -> {
                                List<ECKey> publicKeys = new ArrayList<>(this.getParticipantPublicKeys().stream().map(ECKey::fromPublicOnly).toList());
                                publicKeys.sort(ECKey.PUBKEY_COMPARATOR);
                                Script script = ScriptBuilder.createRedeemScript(this.getParticipantPublicKeys().size(), publicKeys);
                                yield LegacyAddress.fromScriptHash(this.getNetwork().toBitcoinjNetwork(), ScriptPattern.extractHashFromP2PKH(script));
                        }
                        case P2TR -> {
                                List<PublicKey> publicKeys = this.getParticipantPublicKeys().stream().map(PublicKey::parse).toList();
                                XonlyPublicKey aggregatePublicKey = Musig2.aggregateKeys(publicKeys);
                                aggregatePublicKey.tweak(Crypto.TaprootTweak.KeyPathTweak.INSTANCE);
                                yield AddressParser.getDefault().parseAddress(aggregatePublicKey.p2trAddress(new BlockHash(bitcoinConnector.getGensisHash(this.getNetwork()))));
                        }
                        default -> throw new IllegalStateException("Invalid script type, not aupported for aggregation cohort: " + this.getScriptType());
                };
                if (log.isDebugEnabled()) log.debug("For script tyoe " + this.getScriptType() + " and size " + this.size() + " finalized cohort with beacon address: " + this.getBeaconAddress());
        }

        public boolean isFinalizedCohort() {
                return this.getBeaconAddress() != null;
        }

        public URI toAggregateServiceId() {
                if (! isFinalizedCohort()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet finalized.");
                URI aggregateServiceId = URI.create("#" + this.getId());
                if (log.isDebugEnabled()) log.debug("Aggregate service ID: " + aggregateServiceId);
                return aggregateServiceId;
        }

        public String toAggregateServiceType() {
                if (! isFinalizedCohort()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet finalized.");
                String aggregateServiceType = this.getBeaconType().getServiceType();
                if (log.isDebugEnabled()) log.debug("Aggregate service type: " + aggregateServiceType);
                return aggregateServiceType;
        }

        public URI toAggregateServiceEndpoint() {
                if (! isFinalizedCohort()) throw new IllegalStateException("Aggregation cohort " + this.getId() + " not yet finalized.");
                URI aggregateServiceEndpoint = URI.create(BitcoinURI.convertToBitcoinURI(this.getBeaconAddress(), null, null, null));
                if (log.isDebugEnabled()) log.debug("Aggregate service endpoint: " + aggregateServiceEndpoint);
                return aggregateServiceEndpoint;
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

        public List<byte[]> getParticipantPublicKeys() {
                return participantPublicKeys;
        }

        public Address getBeaconAddress() {
                return beaconAddress;
        }

        public Map<DID, byte[]> getCasUpdateHashes() {
                return casUpdateHashes;
        }

        public Map<byte[], byte[]> getSmtUpdateHashes() {
                return smtUpdateHashes;
        }

        public Map<byte[], String> getSmtNonces() {
                return smtNonces;
        }

        public List<String> getMusig2Nonces() {
                return musig2Nonces;
        }

        public Map<DID, byte[]> getBeaconAnnouncementMap() {
                return beaconAnnouncementMap;
        }

        public Map<byte[], SMTProof> getSmtProof() {
                return smtProof;
        }

        public byte[] getUnsignedBeaconSignal() {
                return unsignedBeaconSignal;
        }

        public String getMusig2AggregatedNonce() {
                return musig2AggregatedNonce;
        }
}
