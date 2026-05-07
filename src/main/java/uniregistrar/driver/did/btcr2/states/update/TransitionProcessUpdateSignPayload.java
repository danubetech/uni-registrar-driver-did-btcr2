package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.Transaction;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
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

    public static UpdateState transitionToUpdateSignPayloadFundAddress(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, Address address, Coin minimumValue, AggregationCohort aggregationCohort, BTCR2Update btcr2Update, byte[] updateSignPayload, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(btcr2Update.toJson(), Base64.getEncoder().encodeToString(updateSignPayload), null, null);

        Map<String, Object> jobId = updateJob.toJsonObject();

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("fundAddress");
        didStateAction.putAdditionalProperty("address", address.toString());
        didStateAction.putAdditionalProperty("minimumValue", minimumValue.getValue());

        // REGISTRATION STATE: didRegistrationMetadata

        if (bitcoinConnection != null) didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());
        if (ipfsConnection != null) didRegistrationMetadata.putAll(ipfsConnection.getMetadata());
        if (aggregationCohort != null) didRegistrationMetadata.putAll(aggregationCohort.getMetadata());

        // REGISTRATION STATE: update()

        UpdateState updateState = new UpdateState();
        updateState.setJobId(new RegistrarStateJobId(jobId));
        updateState.setDidState(didStateAction);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }

    public static UpdateState transitionToUpdateSignPayloadCompleteAggregationUpdates(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, AggregationCohort aggregationCohort, BTCR2Update btcr2Update, byte[] updateSignPayload, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(btcr2Update.toJson(), Base64.getEncoder().encodeToString(updateSignPayload), null, null);

        Map<String, Object> jobId = updateJob.toJsonObject();

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("completeAggregationUpdates");
        didStateAction.putAdditionalProperty("aggregationCohort", aggregationCohort.getId());

        // REGISTRATION STATE: didRegistrationMetadata

        if (bitcoinConnection != null) didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());
        if (ipfsConnection != null) didRegistrationMetadata.putAll(ipfsConnection.getMetadata());
        if (aggregationCohort != null) didRegistrationMetadata.putAll(aggregationCohort.getMetadata());

        // create() state

        UpdateState updateState = new UpdateState();
        updateState.setDidState(didStateAction);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }

    public static UpdateState transitionToUtxoSignPayloads(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, BTCR2Update btcr2Update, Transaction unsignedBeaconSignal, List<byte[]> utxoSignPayloads, AggregationCohort aggregationCohort, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(btcr2Update.toJson(), null, Base64.getEncoder().encodeToString(unsignedBeaconSignal.serialize()), utxoSignPayloads.stream().map(x -> Base64.getEncoder().encodeToString(x)).toList());

        Map<String, Object> jobId = updateJob.toJsonObject();

        // REGISTRATION STATE: signing request

        List<SigningRequest> utxoSigningRequests = utxoSignPayloads.stream().map( x -> new SigningRequest()
                        .alg(JWSAlgorithm.ES256KRR)
                        .purpose("capabilityInvocation")
                        .serializedPayload(Base64.getEncoder().encodeToString(x)))
                .toList();
        Map<String, SigningRequest> utxoSigningRequestsMap = new LinkedHashMap<>();
        for (int i=0; i<utxoSigningRequests.size(); i++) {
            utxoSigningRequestsMap.put("utxo" + i, utxoSigningRequests.get(i));
        }

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("signPayload");
        didStateAction.setSigningRequest(utxoSigningRequestsMap);

        // REGISTRATION STATE: didRegistrationMetadata

        if (bitcoinConnection != null) didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());
        if (ipfsConnection != null) didRegistrationMetadata.putAll(ipfsConnection.getMetadata());
        if (aggregationCohort != null) didRegistrationMetadata.putAll(aggregationCohort.getMetadata());

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
