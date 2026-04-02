package uniregistrar.driver.did.btcr2.states.create;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.BitcoinConnector;
import com.danubetech.btc.connection.Network;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.did.DIDDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.crud.create.Create;
import uniregistrar.driver.did.btcr2.job.CreateJob;
import uniregistrar.driver.did.btcr2.ledger.DidDocUnAssembler;
import uniregistrar.openapi.model.CreateRequest;
import uniregistrar.openapi.model.CreateState;

import java.util.LinkedHashMap;
import java.util.Map;

public class StateInit {

    private static final Logger log = LoggerFactory.getLogger(StateInit.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .defaultPropertyInclusion(JsonInclude.Value.ALL_NON_NULL)
            .build();

    public static final int STATE = 0;

    public static CreateState create(CreateJob createJob, CreateRequest createRequest, Create create, BitcoinConnector bitcoinConnector) throws RegistrationException {

        // prepare didRegistrationMetadata and didDocumentMetadata

        Map<String, Object> didRegistrationMetadata = new LinkedHashMap<>();
        Map<String, Object> didDocumentMetadata = new LinkedHashMap<>();

        // read input DID document

        DIDDocument didDocument = jsonMapper.convertValue(createRequest.getDidDocument(), DIDDocument.class);

        // read version and network options

        Integer version = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("version") == null ? null : ((Number) createRequest.getOptions().getAdditionalProperty("version")).intValue());
        Network network = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("network") == null ? null : Network.valueOf((String) createRequest.getOptions().getAdditionalProperty("network")));
        if (version == null) version = 1;
        if (network == null) network = Network.bitcoin;

        // find Bitcoin connection

        BitcoinConnection bitcoinConnection = bitcoinConnector.getBitcoinConnection(network);
        if (bitcoinConnection == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Unknown network: " + network);

        // unassemble initialKey

        byte[] unassembledInitialKey = DidDocUnAssembler.unassembleInitialKey(didDocument);
        if (unassembledInitialKey == null) {
            // next state
            return TransitionInit.transitionToInitGetVerificationMethod(bitcoinConnection, didRegistrationMetadata, didDocumentMetadata);
        }

        // unassemble genesisDocument

        DIDDocument unassembledGenesisDocument = DidDocUnAssembler.unassembleGenesisDocument(didDocument);

        // create()

        uniregistrar.driver.did.btcr2.crud.create.CreateInitResult createInitResult = create.create(bitcoinConnection, unassembledInitialKey, unassembledGenesisDocument, version, network, didDocumentMetadata);

        // next state

        return TransitionInit.transitionToFinished(bitcoinConnection, createInitResult.did(), didRegistrationMetadata, didDocumentMetadata);
    }
}
