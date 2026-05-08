package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import io.ipfs.api.MerkleNode;
import org.bitcoinj.core.Transaction;
import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.openapi.model.DidStateAction;
import uniregistrar.openapi.model.DidStateFinished;
import uniregistrar.openapi.model.UpdateState;

import java.util.Base64;
import java.util.List;
import java.util.Map;

public class TransitionProcessUtxoAggregateSignPayloads {

    public static UpdateState transitionToUtxoAggregateSignPayloadsCompleteAggregationSignatures(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, BTCR2Update btcr2Update, Transaction unsignedBeaconSignal, AggregationCohort aggregationCohort, List<byte[]> utxoAggregateSignPayloads, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(
                btcr2Update.toJson(),
                null,
                Base64.getEncoder().encodeToString(unsignedBeaconSignal.serialize()),
                null,
                utxoAggregateSignPayloads.stream().map(x -> Base64.getEncoder().encodeToString(x)).toList(),
                aggregationCohort.getId());

        Map<String, Object> jobId = updateJob.toJsonObject();

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("completeAggregationSignatures");
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

    public static UpdateState transitionToFinished(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, BTCR2Update btcr2Update, AggregationCohort aggregationCohort, MerkleNode merkleNode, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: didState.state="finished"

        DidStateFinished didStateFinished = new DidStateFinished();
        didStateFinished.setState("finished");

        // REGISTRATION STATE: didRegistrationMetadata

        if (bitcoinConnection != null) didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());
        if (ipfsConnection != null) didRegistrationMetadata.putAll(ipfsConnection.getMetadata());
        if (aggregationCohort != null) didRegistrationMetadata.putAll(aggregationCohort.getMetadata());

        // REGISTRATION STATE: didDocumentMetadata

        if (btcr2Update != null) didDocumentMetadata.put("update", btcr2Update.getJsonObject());
        if (merkleNode != null) didDocumentMetadata.put("updateCid", merkleNode.hash.toString());

        // update state

        UpdateState updateState = new UpdateState();
        updateState.setDidState(didStateFinished);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }
}
