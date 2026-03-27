package uniregistrar.driver.did.btcr2.states.create;

import foundation.identity.did.DID;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnection;
import uniregistrar.driver.did.btcr2.job.Job;
import uniregistrar.driver.did.btcr2.job.JobRegistry;
import uniregistrar.openapi.model.*;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class TransitionInit {

    public static CreateState transitionToInitGetVerificationMethod(BitcoinConnection bitcoinConnection, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // REGISTRATION STATE: verification method template

        VerificationMethodTemplate initialVerificationMethodTemplate = new VerificationMethodTemplate()
                .id("#initialKey")
                .type("Multikey")
                .controller(null)
                .publicKeyJwk(Map.of("kty", "EC", "crv", "secp256k1"))
                .purpose(List.of( "authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation"));

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("getVerificationMethod");
        didStateAction.setVerificationMethodTemplate(Collections.singletonList(initialVerificationMethodTemplate));

        // REGISTRATION STATE: didRegistrationMetadata

        didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());

        // create() state

        CreateState createState = new CreateState();
        createState.setDidState(didStateAction);
        createState.setDidRegistrationMetadata(didRegistrationMetadata);
        createState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return createState;
    }

    public static CreateState transitionToFinished(JobRegistry jobRegistry, Job job, BitcoinConnection bitcoinConnection, DID did, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: jobId

        if (job != null) jobRegistry.removeJob(job);

        // REGISTRATION STATE: verification method templates

        VerificationMethodTemplate initialVerificationMethodTemplate = new VerificationMethodTemplate()
                .id("#initialKey")
                .type("Multikey")
                .controller(null)
                .publicKeyJwk(Map.of("kty", "EC", "crv", "secp256k1"))
                .purpose(List.of( "authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation"));

        VerificationMethodTemplate finishedVerificationMethodTemplate = new VerificationMethodTemplate()
                .id(did + "#initialKey")
                .controller(did.getDidString());

        List<VerificationMethodTemplate> verificationMethodList = List.of(initialVerificationMethodTemplate, finishedVerificationMethodTemplate);

        // REGISTRATION STATE: didState.secret

        DidStateSecret didStateSecret = new DidStateSecret();

        DidStateSecretVerificationMethodInner didStateSecretVerificationMethodInner = new DidStateSecretVerificationMethodInner();
        didStateSecretVerificationMethodInner.setActualInstance(verificationMethodList);

        didStateSecret.setVerificationMethod(Collections.singletonList(didStateSecretVerificationMethodInner));

        // REGISTRATION STATE: didState.state="finished"

        DidStateFinished didStateFinished = new DidStateFinished();
        didStateFinished.setState("finished");
        didStateFinished.setDid(did.getDidString());
        didStateFinished.setSecret(didStateSecret);

        // REGISTRATION STATE: didRegistrationMetadata

        didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());

        // create() state

        CreateState createState = new CreateState();
        createState.setDidState(didStateFinished);
        createState.setDidRegistrationMetadata(didRegistrationMetadata);
        createState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return createState;
    }
}
