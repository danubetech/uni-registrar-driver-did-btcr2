package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
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

    public static UpdateState transitionToUpdateSignPayload(BitcoinConnection bitcoinConnection, URI verificationMethodId, byte[] updateSignPayload, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: jobId

        UpdateJob updateJob = new UpdateJob(Base64.getEncoder().encodeToString(updateSignPayload), null, null);

        Map<String, Object> jobId = updateJob.toJsonObject();

        // REGISTRATION STATE: signing request

        SigningRequest didUpdateSigningRequest = new SigningRequest()
                .kid(verificationMethodId.toString())
                .alg(JWSAlgorithm.ES256KS)
                .purpose("capabilityInvocation")
                .serializedPayload(Base64.getEncoder().encodeToString(updateSignPayload));

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("signPayload");
        didStateAction.setSigningRequest(Map.of("btcr2Update", didUpdateSigningRequest));

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
