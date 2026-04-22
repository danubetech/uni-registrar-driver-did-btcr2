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
import io.ipfs.api.MerkleNode;
import io.ipfs.api.NamedStreamable;
import org.bitcoinj.base.AddressParser;
import org.bitcoinj.uri.BitcoinURI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.crud.create.Create;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.ipfs.IPFSPublishService;
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

        // read version and network and publishToIpfs and genesisInitialKey and genesisStandardBeacons options

        Integer version = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("version") == null ? null : ((Number) createRequest.getOptions().getAdditionalProperty("version")).intValue());
        Network network = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("network") == null ? null : Network.valueOf((String) createRequest.getOptions().getAdditionalProperty("network")));
        Boolean publishToIpfs = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("publishToIpfs") == null ? null : (Boolean) createRequest.getOptions().getAdditionalProperty("publishToIpfs"));
        Boolean genesisInitialKey = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("genesisInitialKey") == null ? null : (Boolean) createRequest.getOptions().getAdditionalProperty("genesisInitialKey"));
        Boolean genesisStandardBeacons = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("genesisStandardBeacons") == null ? null : (Boolean) createRequest.getOptions().getAdditionalProperty("genesisStandardBeacons"));
        if (version == null) version = 1;
        if (network == null) network = Network.bitcoin;
        if (publishToIpfs == null) publishToIpfs = Boolean.TRUE;
        if (genesisInitialKey == null) genesisInitialKey = Boolean.TRUE;
        if (genesisStandardBeacons == null) genesisStandardBeacons = Boolean.TRUE;

        // find Bitcoin connection

        BitcoinConnection bitcoinConnection = bitcoinConnector.getBitcoinConnection(network);
        if (bitcoinConnection == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Unknown network: " + network);

        // unassemble initialKey

        byte[] unassembledInitialKey = DidDocUnAssembler.unassembleInitialKey(didDocument);
        if (unassembledInitialKey == null && genesisInitialKey) {
            // next state
            return TransitionInit.transitionToInitGetVerificationMethod(bitcoinConnection, ipfsConnection, didRegistrationMetadata, didDocumentMetadata);
        }

        // unassemble genesisDocument

        DIDDocumentV1_1 unassembledGenesisDocument = DidDocUnAssembler.unassembleGenesisDocument(didDocument);

        // add standard beacons?

        if (unassembledInitialKey != null && unassembledGenesisDocument != null && genesisStandardBeacons) {

            AddressParser addressParser = AddressParser.getDefault();
            PublicKey initialPublicKey = PublicKey.parse(unassembledInitialKey);

            String p2pkh_bitcoin_address = BitcoinURI.convertToBitcoinURI(network.toBitcoinjNetwork(), addressParser.parseAddress(initialPublicKey.p2pkhAddress(new BlockHash(bitcoinConnector.getGensisHash(network)))).toString(), null, null, null);
            String p2wpkh_bitcoin_address = BitcoinURI.convertToBitcoinURI(network.toBitcoinjNetwork(), addressParser.parseAddress(initialPublicKey.p2wpkhAddress(new BlockHash(bitcoinConnector.getGensisHash(network)))).toString(), null, null, null);
            String p2tr_bitcoin_address = BitcoinURI.convertToBitcoinURI(network.toBitcoinjNetwork(), addressParser.parseAddress(initialPublicKey.p2trAddress(new BlockHash(bitcoinConnector.getGensisHash(network)))).toString(), null, null, null);

            unassembledGenesisDocument = DIDDocumentV1_1.builder()
                    .base(unassembledGenesisDocument)
                    .defaultContexts(false)
                    .services(List.of(
                            Service.builder()
                                    .id(URI.create("#initialP2PKH"))
                                    .type("SingletonBeacon")
                                    .serviceEndpoint(URI.create(p2pkh_bitcoin_address))
                                    .build(),
                            Service.builder()
                                    .id(URI.create("#initialP2WPKH"))
                                    .type("SingletonBeacon")
                                    .serviceEndpoint(URI.create(p2wpkh_bitcoin_address))
                                    .build(),
                            Service.builder()
                                    .id(URI.create("#initialP2TR"))
                                    .type("SingletonBeacon")
                                    .serviceEndpoint(URI.create(p2tr_bitcoin_address))
                                    .build()))
                    .build();
        }

        // create()

        uniregistrar.driver.did.btcr2.crud.create.CreateInitResult createInitResult = create.create(bitcoinConnection, unassembledInitialKey, unassembledGenesisDocument, version, network, didDocumentMetadata);

        // publish to IPFS?

        MerkleNode merkleNode = null;
        if (publishToIpfs && ipfsConnection != null && createInitResult.genesisDocument() != null) {
            try {
                byte[] ipfsPayload = createInitResult.genesisDocument().toString().getBytes(StandardCharsets.UTF_8);
                merkleNode = ipfsConnection.getIpfs().add(new NamedStreamable.ByteArrayWrapper(ipfsPayload)).getFirst();
            } catch (IOException ex) {
                throw new RegistrationException(RegistrationException.ERROR_INTERNAL_ERROR, "Cannot publish to IPFS: " + ex.getMessage(), ex);
            }
            if (log.isDebugEnabled()) log.debug("Published genesisDocument to IPFS: " + merkleNode.hash);
        }

        // next state

        return TransitionInit.transitionToFinished(bitcoinConnection, ipfsConnection, createInitResult.initialKey(), createInitResult.genesisDocument(), createInitResult.did(), merkleNode, didRegistrationMetadata, didDocumentMetadata);
    }
}
