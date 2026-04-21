package uniregistrar.driver.did.btcr2.states.create;

import com.danubetech.btc.connection.BitcoinConnection;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import org.apache.commons.codec.binary.Hex;
import uniregistrar.RegistrationException;
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

    public static CreateState transitionToFinished(BitcoinConnection bitcoinConnection, byte[] initialKey, DIDDocument genesisDocument, DID did, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: jobId

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

        // REGISTRATION STATE: didDocumentMetadata

        didDocumentMetadata.put("initialKey", initialKey == null ? null : Hex.encodeHexString(initialKey));
        didDocumentMetadata.put("genesisDocument", genesisDocument == null ? null : genesisDocument.toMap());

        // create() state

        CreateState createState = new CreateState();
        createState.setDidState(didStateFinished);
        createState.setDidRegistrationMetadata(didRegistrationMetadata);
        createState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return createState;
    }
}
