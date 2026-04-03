package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.openapi.model.DidStateFinished;
import uniregistrar.openapi.model.UpdateState;

import java.util.Map;

public class TransitionProcessUtxoSignPayloads {

    public static UpdateState transitionToFinished(BitcoinConnection bitcoinConnection, BTCR2Update btcr2Update, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: didState.state="finished"

        DidStateFinished didStateFinished = new DidStateFinished();
        didStateFinished.setState("finished");

        // REGISTRATION STATE: didRegistrationMetadata

        didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());

        // REGISTRATION STATE: didDocumentMetadata

        didDocumentMetadata.put("btcr2Update", btcr2Update.getJsonObject());

        // update state

        UpdateState updateState = new UpdateState();
        updateState.setDidState(didStateFinished);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }
}
