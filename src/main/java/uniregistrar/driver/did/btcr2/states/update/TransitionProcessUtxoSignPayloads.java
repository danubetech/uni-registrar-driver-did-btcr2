package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import foundation.identity.did.DID;
import uniregistrar.openapi.model.DidStateFinished;
import uniregistrar.openapi.model.UpdateState;

import java.util.Map;

public class TransitionProcessUtxoSignPayloads {

    public static UpdateState transitionToFinished(BitcoinConnection bitcoinConnection, DID did, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: didState.state="finished"

        DidStateFinished didStateFinished = new DidStateFinished();
        didStateFinished.setState("finished");
        didStateFinished.setDid(did.getDidString());

        // REGISTRATION STATE: didRegistrationMetadata

        didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());

        // update() state

        UpdateState updateState = new UpdateState();
        updateState.setDidState(didStateFinished);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }
}
