package uniregistrar.driver.did.btcr2.states.create;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.BitcoinConnector;
import com.danubetech.btc.connection.Network;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.DIDDocumentV1_1;
import foundation.identity.did.Service;
import fr.acinq.bitcoin.BlockHash;
import fr.acinq.bitcoin.PublicKey;
import io.ipfs.api.AddArgs;
import io.ipfs.api.MerkleNode;
import io.ipfs.api.NamedStreamable;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.AddressParser;
import org.bitcoinj.uri.BitcoinURI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;
import uniregistrar.driver.did.btcr2.aggregation.AggregationService;
import uniregistrar.driver.did.btcr2.algorithms.JSONDocumentHashing;
import uniregistrar.driver.did.btcr2.crud.create.Create;
import uniregistrar.driver.did.btcr2.crud.create.CreateInitResult;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.job.CreateJob;
import uniregistrar.driver.did.btcr2.ledger.DidDocUnAssembler;
import uniregistrar.openapi.model.CreateRequest;
import uniregistrar.openapi.model.CreateState;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class StateInit {

    private static final Logger log = LoggerFactory.getLogger(StateInit.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .defaultPropertyInclusion(JsonInclude.Value.ALL_NON_NULL)
            .build();

    public static final int STATE = 0;

    public static CreateState create(CreateJob createJob, CreateRequest createRequest, Create create, BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) throws RegistrationException {

        // prepare didRegistrationMetadata and didDocumentMetadata

        Map<String, Object> didRegistrationMetadata = new LinkedHashMap<>();
        Map<String, Object> didDocumentMetadata = new LinkedHashMap<>();

        // read input DID document

        DIDDocument didDocument = jsonMapper.convertValue(createRequest.getDidDocument(), DIDDocument.class);

        // read version and network and publishToIpfs and generateInitialKey and generateStandardBeacons options

        Integer version = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("version") == null ? null : ((Number) createRequest.getOptions().getAdditionalProperty("version")).intValue());
        Network network = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("network") == null ? null : Network.valueOf((String) createRequest.getOptions().getAdditionalProperty("network")));
        Boolean publishToIpfs = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("publishToIpfs") == null ? null : (Boolean) createRequest.getOptions().getAdditionalProperty("publishToIpfs"));
        Boolean generateInitialKey = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("generateInitialKey") == null ? null : (Boolean) createRequest.getOptions().getAdditionalProperty("generateInitialKey"));
        Boolean generateStandardBeacons = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("generateStandardBeacons") == null ? null : (Boolean) createRequest.getOptions().getAdditionalProperty("generateStandardBeacons"));
        String generateAggregateBeacon = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("generateAggregateBeacon") == null ? null : (String) createRequest.getOptions().getAdditionalProperty("generateAggregateBeacon"));
        if (version == null) version = 1;
        if (network == null) network = Network.bitcoin;
        if (publishToIpfs == null) publishToIpfs = Boolean.TRUE;
        if (generateInitialKey == null) generateInitialKey = Boolean.TRUE;
        if (generateStandardBeacons == null) generateStandardBeacons = Boolean.FALSE;
        if (generateAggregateBeacon == null || generateAggregateBeacon.isBlank()) generateAggregateBeacon = null;

        // find Bitcoin connection

        BitcoinConnection bitcoinConnection = bitcoinConnector.getBitcoinConnection(network);
        if (bitcoinConnection == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Unknown network: " + network);

        // unassemble initialKey

        byte[] unassembledInitialKey = DidDocUnAssembler.unassembleInitialKey(didDocument);

        // unassemble genesisDocument

        DIDDocumentV1_1 unassembledGenesisDocument = DidDocUnAssembler.unassembleGenesisDocument(didDocument, unassembledInitialKey == null);

        // generate initial key?

        if (generateInitialKey) {

            if (unassembledInitialKey == null) {
                // next state
                return TransitionInit.transitionToInitGetVerificationMethod(bitcoinConnection, ipfsConnection, didRegistrationMetadata, didDocumentMetadata);
            }

            if (log.isDebugEnabled()) log.debug("Generated initial key: " + Hex.encodeHexString(unassembledInitialKey));
        }

        // generate standard beacons?

        if (generateStandardBeacons) {

            if (unassembledInitialKey == null) {
                throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot generate standard beacons without initial key. Try setting option `generateInitialKey: true`.");
            }

            if (unassembledGenesisDocument == null) {
                unassembledGenesisDocument = DIDDocumentV1_1.builder().defaultContexts(true).context(DidDocUnAssembler.JSONLD_CONTEXT_BTCR2_V1).id(DidDocUnAssembler.GENESIS_DID).build();
            }

            AddressParser addressParser = AddressParser.getDefault();
            PublicKey initialPublicKey = PublicKey.parse(unassembledInitialKey);

            URI p2pkhServiceEndpoint = URI.create(BitcoinURI.convertToBitcoinURI(addressParser.parseAddress(initialPublicKey.p2pkhAddress(new BlockHash(bitcoinConnector.getGensisHash(network)))), null, null, null));
            URI p2wpkhServiceEndpoint = URI.create(BitcoinURI.convertToBitcoinURI(addressParser.parseAddress(initialPublicKey.p2wpkhAddress(new BlockHash(bitcoinConnector.getGensisHash(network)))), null, null, null));
            URI p2trServiceEndpoint = URI.create(BitcoinURI.convertToBitcoinURI(addressParser.parseAddress(initialPublicKey.p2trAddress(new BlockHash(bitcoinConnector.getGensisHash(network)))), null, null, null));

            unassembledGenesisDocument = DIDDocumentV1_1.builder()
                    .base(unassembledGenesisDocument)
                    .defaultContexts(false)
                    .services(List.of(
                            Service.builder()
                                    .id(URI.create("#initialP2PKH"))
                                    .type("SingletonBeacon")
                                    .serviceEndpoint(p2pkhServiceEndpoint)
                                    .build(),
                            Service.builder()
                                    .id(URI.create("#initialP2WPKH"))
                                    .type("SingletonBeacon")
                                    .serviceEndpoint(p2wpkhServiceEndpoint)
                                    .build(),
                            Service.builder()
                                    .id(URI.create("#initialP2TR"))
                                    .type("SingletonBeacon")
                                    .serviceEndpoint(p2trServiceEndpoint)
                                    .build()))
                    .build();

            if (log.isDebugEnabled()) log.debug("Generated standard beacons: " + unassembledGenesisDocument);
        }

        // generate aggregate beacon?

        if (generateAggregateBeacon != null) {

            if (unassembledInitialKey == null) {
                throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot generate standard beacons without initial key. Try setting option `generateInitialKey: true`.");
            }

            if (unassembledGenesisDocument == null) {
                unassembledGenesisDocument = DIDDocumentV1_1.builder().defaultContexts(true).context(DidDocUnAssembler.JSONLD_CONTEXT_BTCR2_V1).id(DidDocUnAssembler.GENESIS_DID).build();
            }

            AggregationCohort aggregationCohort = AggregationService.getAggregationCohort(generateAggregateBeacon);
            if (aggregationCohort == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Unknown aggregation cohort: " + generateAggregateBeacon);

            // DID controllers that wish to join an Aggregation Cohort and become an Aggregation Participant would need to provide the Aggregation Service with a Schnorr public key.

            if (! aggregationCohort.containsParticipantPublicKey(unassembledInitialKey)) {
                aggregationCohort.addParticipantPublicKey(unassembledInitialKey);
            }

            // The Aggregation Service decides when to finalize the membership of the Aggregation Cohort.

            if (! aggregationCohort.isCompletedCohort()) {
                // next state
                return TransitionInit.transitionToInitCompleteAggregationCohort(bitcoinConnection, ipfsConnection, aggregationCohort, didRegistrationMetadata, didDocumentMetadata);
            }

            if (! aggregationCohort.isFinalizedCohort()) {
                aggregationCohort.finalizeCohort(bitcoinConnector);
            }

            // This Beacon Address must be sent to all Aggregation Participants with the set of keys used to construct it.

            URI aggregateServiceId = aggregationCohort.toAggregateServiceId();
            String aggregateServiceType = aggregationCohort.toAggregateServiceType();
            URI aggregateServiceEndpoint = aggregationCohort.toAggregateServiceEndpoint();

            // Once the Aggregation Participants have verified the newly formed Beacon Address, they can construct the service object that can be included within their DID document’s service array.

            unassembledGenesisDocument = DIDDocumentV1_1.builder()
                    .base(unassembledGenesisDocument)
                    .defaultContexts(false)
                    .services(List.of(
                            Service.builder()
                                    .id(aggregateServiceId)
                                    .type(aggregateServiceType)
                                    .serviceEndpoint(aggregateServiceEndpoint)
                                    .build()))
                    .build();

            if (log.isDebugEnabled()) log.debug("Generated aggregate beacon: " + unassembledGenesisDocument);
        }

        // create()

        CreateInitResult createInitResult = create.createInit(bitcoinConnection, unassembledInitialKey, unassembledGenesisDocument, version, network, didDocumentMetadata);

        // publish to IPFS?

        MerkleNode merkleNode = null;
        if (publishToIpfs && ipfsConnection != null && createInitResult.genesisDocument() != null) {
            try {
                byte[] ipfsPayload = JSONDocumentHashing.jsonDocumentCanonicalizing(createInitResult.genesisDocument().toJson()).getBytes(StandardCharsets.UTF_8);
                AddArgs addArgs = AddArgs.Builder.newInstance().setCidVersion(1).setRawLeaves().setHash("sha2-256").setPin().build();
                merkleNode = ipfsConnection.getIpfs().add(new NamedStreamable.ByteArrayWrapper(ipfsPayload), addArgs).getFirst();
            } catch (IOException ex) {
                throw new RegistrationException(RegistrationException.ERROR_INTERNAL_ERROR, "Cannot publish to IPFS: " + ex.getMessage(), ex);
            }
            if (log.isDebugEnabled()) log.debug("Published genesisDocument to IPFS: " + merkleNode.hash);
        }

        // next state

        return TransitionInit.transitionToFinished(bitcoinConnection, ipfsConnection, createInitResult.initialKey(), createInitResult.genesisDocument(), createInitResult.did(), merkleNode, didRegistrationMetadata, didDocumentMetadata);
    }
}
