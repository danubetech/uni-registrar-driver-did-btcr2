package uniregistrar.driver.did.btcr2.states.update;

import foundation.identity.did.DID;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnection;
import uniregistrar.driver.did.btcr2.job.Job;
import uniregistrar.driver.did.btcr2.job.JobRegistry;
import uniregistrar.openapi.model.*;

import java.net.URI;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class TransitionInit {

    public static UpdateState transitionToInitGetVerificationMethod(BitcoinConnection bitcoinConnection, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: verification method template

        VerificationMethodTemplate capabilityInvocationVerificationMethodTemplate = new VerificationMethodTemplate()
                .publicKeyJwk(Map.of("kty", "EC", "crv", "secp256k1"))
                .purpose(List.of("capabilityInvocation"));

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("getVerificationMethod");
        didStateAction.setVerificationMethodTemplate(Collections.singletonList(capabilityInvocationVerificationMethodTemplate));

        // REGISTRATION STATE: didRegistrationMetadata

        didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());

        // REGISTRATION STATE: update()

        UpdateState updateState = new UpdateState();
        updateState.setDidState(didStateAction);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }

    public static UpdateState transitionToSignPayload(BitcoinConnection bitcoinConnection, URI verificationMethodID, byte[] serializedPayload, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: signing requesst

        SigningRequest didUpdateSigningRequest = new SigningRequest()
                .kid(verificationMethodID.toString())
                .serializedPayload(Base64.getUrlEncoder().encodeToString(serializedPayload));

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("signPayload");
        didStateAction.setSigningRequest(Map.of("didUpdate", didUpdateSigningRequest));

        // REGISTRATION STATE: didRegistrationMetadata

        didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());

        // REGISTRATION STATE: update()

        UpdateState updateState = new UpdateState();
        updateState.setDidState(didStateAction);
        updateState.setDidRegistrationMetadata(didRegistrationMetadata);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return updateState;
    }

    public static UpdateState transitionToFinished(JobRegistry jobRegistry, Job job, BitcoinConnection bitcoinConnection, DID did, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: jobId

        if (job != null) jobRegistry.removeJob(job);

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
