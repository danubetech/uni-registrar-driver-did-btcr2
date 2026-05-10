package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import io.ipfs.api.MerkleNode;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.openapi.model.DidStateFinished;
import uniregistrar.openapi.model.UpdateState;

import java.util.Map;

public class TransitionProcessUtxoSingletonSignPayloads {

    public static UpdateState transitionToFinished(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, String txId, BTCR2Update update, MerkleNode merkleNodeUpdate, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: didState.state="finished"

        DidStateFinished didStateFinished = new DidStateFinished();
        didStateFinished.setState("finished");

        // REGISTRATION STATE: didRegistrationMetadata

        if (bitcoinConnection != null) didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());
        if (ipfsConnection != null) didRegistrationMetadata.putAll(ipfsConnection.getMetadata());

        // REGISTRATION STATE: didDocumentMetadata

        if (txId != null) didDocumentMetadata.put("txId", txId);
        if (update != null) didDocumentMetadata.put("update", update.getJsonObject());
        if (merkleNodeUpdate != null) didDocumentMetadata.put("updateCid", merkleNodeUpdate.hash.toString());

        // update state

        UpdateState updateState = new UpdateState();
        updateState.setDidState(didStateFinished);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }
}
