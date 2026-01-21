package uniregistrar.driver.did.btcr2.states.update;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.parser.ParserException;
import fr.acinq.secp256k1.Hex;
import io.ipfs.multibase.Multibase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.Network;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnection;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.crud.update.Update;
import uniregistrar.driver.did.btcr2.job.Job;
import uniregistrar.driver.did.btcr2.job.JobRegistry;
import uniregistrar.driver.did.btcr2.ledger.DidDocUnAssembler;
import uniregistrar.driver.did.btcr2.util.MulticodecUtil;
import uniregistrar.openapi.model.DidDocument;
import uniregistrar.openapi.model.UpdateRequest;
import uniregistrar.openapi.model.UpdateState;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class StateInit {

    private static final Logger log = LoggerFactory.getLogger(StateInit.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static final int STATE = 0;

    static {
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    public static UpdateState update(JobRegistry jobRegistry, Job job, UpdateRequest updateRequest, Update update, BitcoinConnector bitcoinConnector) throws RegistrationException {

        // read input fields

        DID did;
        try {
            did = DID.fromString(updateRequest.getDid());
        } catch (ParserException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid DID: " + updateRequest.getDid());
        }

        List<DidDocument> didDocumentList = updateRequest.getDidDocument();
        DIDDocument didDocument = (didDocumentList == null || didDocumentList.isEmpty()) ? null : objectMapper.convertValue(didDocumentList.getFirst(), DIDDocument.class);

        Network network = updateRequest.getOptions() == null ? null : (updateRequest.getOptions().getAdditionalProperty("network") == null ? null : Network.valueOf((String) updateRequest.getOptions().getAdditionalProperty("network")));
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

        // prepare pubKeyBytes

        byte[] pubKeyBytes = MulticodecUtil.removeMulticodec(Multibase.decode(unassembledBtcr2InitialKey), MulticodecUtil.MULTICODEC_SECP256K1_PUB);
        if (log.isDebugEnabled()) log.debug("pubKeyBytes: {}", Hex.encode(pubKeyBytes));

        // prepare sourceDocument

        DIDDocument sourceDocument = didDocument;
        if (log.isDebugEnabled()) log.debug("sourceDocument: {}", sourceDocument == null ? null : sourceDocument.toJson());

        // DID DOCUMENT METADATA

        Map<String, Object> didDocumentMetadata = new LinkedHashMap<>();

        // update

        List<Map<String, Object>> signalsMetadata = update.update(did, sourceDocument, /* TODO */ null, /* TODO */ null, /* TODO */ null, /* TODO */ null, didDocumentMetadata);

        // next state

        return TransitionInit.transitionToFinished(jobRegistry, job, bitcoinConnection, /* TODO */ null, didDocumentMetadata);
    }
}
