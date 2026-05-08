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

    public static UpdateState transitionToUpdateSignPayloadFundAddress(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, BTCR2Update btcr2Update, byte[] updateSignPayload, Address address, Coin minimumValue, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(
                btcr2Update.toJson(),
                Base64.getEncoder().encodeToString(updateSignPayload),
                null,
                null,
                null,
                null);

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

        // REGISTRATION STATE: update()

        UpdateState updateState = new UpdateState();
        updateState.setJobId(new RegistrarStateJobId(jobId));
        updateState.setDidState(didStateAction);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }

    public static UpdateState transitionToUpdateSignPayloadCompleteAggregationUpdates(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, BTCR2Update btcr2Update, byte[] updateSignPayload, AggregationCohort aggregationCohort, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(
                btcr2Update.toJson(),
                Base64.getEncoder().encodeToString(updateSignPayload),
                null,
                null,
                null,
                null);

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

    public static UpdateState transitionToUtxoSingletonSignPayloads(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, BTCR2Update btcr2Update, Transaction unsignedBeaconSignal, List<byte[]> utxoSingletonSignPayloads, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(
                btcr2Update.toJson(),
                null,
                Base64.getEncoder().encodeToString(unsignedBeaconSignal.serialize()),
                utxoSingletonSignPayloads.stream().map(x -> Base64.getEncoder().encodeToString(x)).toList(),
                null,
                null);

        Map<String, Object> jobId = updateJob.toJsonObject();

        // REGISTRATION STATE: signing request

        List<SigningRequest> utxoSingletonSigningRequests = utxoSingletonSignPayloads.stream().map( x -> new SigningRequest()
                        .alg(JWSAlgorithm.ES256KRR)
                        .purpose("capabilityInvocation")
                        .serializedPayload(Base64.getEncoder().encodeToString(x)))
                .toList();
        Map<String, SigningRequest> utxoSingletonSigningRequestsMap = new LinkedHashMap<>();
        for (int i=0; i<utxoSingletonSigningRequests.size(); i++) {
            utxoSingletonSigningRequestsMap.put("utxoSingleton" + i, utxoSingletonSigningRequests.get(i));
        }

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("signPayload");
        didStateAction.setSigningRequest(utxoSingletonSigningRequestsMap);

        // REGISTRATION STATE: didRegistrationMetadata

        if (bitcoinConnection != null) didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());
        if (ipfsConnection != null) didRegistrationMetadata.putAll(ipfsConnection.getMetadata());

        // REGISTRATION STATE: update()

        UpdateState updateState = new UpdateState();
        updateState.setJobId(new RegistrarStateJobId(jobId));
        updateState.setDidState(didStateAction);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }

    public static UpdateState transitionToUtxoAggregateSignPayloads(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, BTCR2Update btcr2Update, Transaction unsignedBeaconSignal, List<byte[]> utxoAggregateSignPayloads, AggregationCohort aggregationCohort, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(
                btcr2Update.toJson(),
                null,
                Base64.getEncoder().encodeToString(unsignedBeaconSignal.serialize()),
                null,
                utxoAggregateSignPayloads.stream().map(x -> Base64.getEncoder().encodeToString(x)).toList(),
                aggregationCohort.getId());

        Map<String, Object> jobId = updateJob.toJsonObject();

        // REGISTRATION STATE: signing request

        List<SigningRequest> utxoAggregateSigningRequests = utxoAggregateSignPayloads.stream().map( x -> new SigningRequest()
                        .alg("MUSIG2")
                        .purpose("capabilityInvocation")
                        .serializedPayload(Base64.getEncoder().encodeToString(x)))
                .toList();
        Map<String, SigningRequest> utxoAggregateSigningRequestsMap = new LinkedHashMap<>();
        for (int i=0; i<utxoAggregateSigningRequests.size(); i++) {
            utxoAggregateSigningRequestsMap.put("utxoAggregate" + i, utxoAggregateSigningRequests.get(i));
        }

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("signPayload");
        didStateAction.setSigningRequest(utxoAggregateSigningRequestsMap);

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
