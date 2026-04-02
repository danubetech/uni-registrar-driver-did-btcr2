package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.openapi.model.DidStateAction;
import uniregistrar.openapi.model.RegistrarStateJobId;
import uniregistrar.openapi.model.SigningRequest;
import uniregistrar.openapi.model.UpdateState;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class TransitionProcessUpdateSignPayload {

    public static UpdateState transitionToUpdateSignPayloadFundAddress(BitcoinConnection bitcoinConnection, byte[] updateSignPayload, Address address, Coin minimumValue, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(Base64.getEncoder().encodeToString(updateSignPayload), null, null);

        Map<String, Object> jobId = updateJob.toJsonObject();

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("fundAddress");
        didStateAction.putAdditionalProperty("address", address.toString());
        didStateAction.putAdditionalProperty("minimumValue", minimumValue.getValue());

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

    public static UpdateState transitionToUtxoSignPayloads(BitcoinConnection bitcoinConnection, byte[] btcr2UpdateAnnouncement, List<byte[]> utxoSignPayloads, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(null, Base64.getEncoder().encodeToString(btcr2UpdateAnnouncement), utxoSignPayloads.stream().map(x -> Base64.getEncoder().encodeToString(x)).toList());

        Map<String, Object> jobId = updateJob.toJsonObject();

        // REGISTRATION STATE: signing request

        List<SigningRequest> utxoSigningRequests = utxoSignPayloads.stream().map( x -> new SigningRequest()
                        .alg(JWSAlgorithm.ES256KS)
                        .purpose("capabilityInvocation")
                        .serializedPayload(Base64.getEncoder().encodeToString(x)))
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
