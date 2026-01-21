package uniregistrar.driver.did.btcr2.states.create;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import fr.acinq.secp256k1.Hex;
import io.ipfs.multibase.Multibase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.Network;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnection;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.crud.create.Create;
import uniregistrar.driver.did.btcr2.job.Job;
import uniregistrar.driver.did.btcr2.job.JobRegistry;
import uniregistrar.driver.did.btcr2.ledger.DidDocUnAssembler;
import uniregistrar.driver.did.btcr2.util.MulticodecUtil;
import uniregistrar.openapi.model.CreateRequest;
import uniregistrar.openapi.model.CreateState;

import java.util.LinkedHashMap;
import java.util.Map;

public class StateInit {

    private static final Logger log = LoggerFactory.getLogger(StateInit.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static final int STATE = 0;

    static {
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    public static CreateState create(JobRegistry jobRegistry, Job job, CreateRequest createRequest, Create create, BitcoinConnector bitcoinConnector) throws RegistrationException {

        // read input fields

        DIDDocument didDocument = objectMapper.convertValue(createRequest.getDidDocument(), DIDDocument.class);

        Integer version = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("version") == null ? null : ((Number) createRequest.getOptions().getAdditionalProperty("version")).intValue());

        Network network = createRequest.getOptions() == null ? null : (createRequest.getOptions().getAdditionalProperty("network") == null ? null : Network.valueOf((String) createRequest.getOptions().getAdditionalProperty("network")));
        if (network == null) network = Network.bitcoin;

        // find Bitcoin connection

        BitcoinConnection bitcoinConnection = bitcoinConnector.getBitcoinConnection(network);
        if (bitcoinConnection == null) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Unknown network: " + network);
        }

        // unassemble btcr2InitialKey

        String unassembledBtcr2InitialKey = DidDocUnAssembler.unassembleBtcr2InitialKey(didDocument);

        if (unassembledBtcr2InitialKey == null) {

            // next state

            return TransitionInit.transitionToInitGetVerificationMethod(bitcoinConnection);
        }

        // unassemble DID document content

        Map<String, Object> unassembledDIDDocumentContent = DidDocUnAssembler.unassembleDIDDocumentContent(didDocument);

        // prepare pubKeyBytes

        byte[] pubKeyBytes = MulticodecUtil.removeMulticodec(Multibase.decode(unassembledBtcr2InitialKey), MulticodecUtil.MULTICODEC_SECP256K1_PUB);
        if (log.isDebugEnabled()) log.debug("pubKeyBytes: {}", Hex.encode(pubKeyBytes));

        // prepare intermediateDocument

        DIDDocument intermediateDocument = unassembledDIDDocumentContent == null ? null : didDocument;
        if (log.isDebugEnabled()) log.debug("intermediateDocument: {}", intermediateDocument == null ? null : intermediateDocument.toJson());

        // DID DOCUMENT METADATA

        Map<String, Object> didDocumentMetadata = new LinkedHashMap<>();

        // create

        Map.Entry<DID, DIDDocument> didAndInitialDocument = create.create(pubKeyBytes, intermediateDocument, version, network, didDocumentMetadata);

        // next state

        return TransitionInit.transitionToFinished(jobRegistry, job, bitcoinConnection, didAndInitialDocument.getKey().getDidString(), didDocumentMetadata);
    }
}
