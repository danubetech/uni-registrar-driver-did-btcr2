package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import foundation.identity.did.DID;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.openapi.model.*;

import java.net.URI;
import java.util.*;

public class TransitionProcessUpdateSignPayload {

    public static UpdateState transitionToUtxoSignPayloads(BitcoinConnection bitcoinConnection, byte[] btcr2UpdateAnnouncement, List<byte[]> utxoSignPayloads, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(Base64.getUrlEncoder().encodeToString(btcr2UpdateAnnouncement), null, utxoSignPayloads.stream().map(x -> Base64.getUrlEncoder().encodeToString(x)).toList());

        Map<String, Object> jobId = updateJob.toJsonObject();

        // REGISTRATION STATE: signing request

        List<SigningRequest> utxoSigningRequests = utxoSignPayloads.stream().map( x -> new SigningRequest()
                        .purpose("capabilityInvocation")
                        .serializedPayload(Base64.getUrlEncoder().encodeToString(x)))
                .toList();
        Map<String, SigningRequest> utxoSigningRequestsMap = new LinkedHashMap<>();
        for (int i=0; i<utxoSigningRequests.size(); i++) {
            utxoSigningRequestsMap.put("btcr2Utxo" + i, utxoSigningRequests.get(i));
        }

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("signPayload");
        didStateAction.setSigningRequest(utxoSigningRequestsMap);

        // REGISTRATION STATE: didRegistrationMetadata

        didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());

        // REGISTRATION STATE: update()

        UpdateState updateState = new UpdateState();
        updateState.setJobId(new RegistrarStateJobId(jobId));
        updateState.setDidState(didStateAction);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }
}
