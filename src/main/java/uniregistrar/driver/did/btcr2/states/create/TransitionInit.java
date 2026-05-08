package uniregistrar.driver.did.btcr2.states.create;

import com.danubetech.btc.connection.BitcoinConnection;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import io.ipfs.api.MerkleNode;
import org.apache.commons.codec.binary.Hex;
import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.util.BytesArray;
import uniregistrar.openapi.model.*;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class TransitionInit {

    public static CreateState transitionToInitGetVerificationMethod(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

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

        if (bitcoinConnection != null) didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());
        if (ipfsConnection != null) didRegistrationMetadata.putAll(ipfsConnection.getMetadata());

        // create() state

        CreateState createState = new CreateState();
        createState.setDidState(didStateAction);
        createState.setDidRegistrationMetadata(didRegistrationMetadata);
        createState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return createState;
    }

    public static CreateState transitionToInitCompleteAggregationCohort(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, AggregationCohort aggregationCohort, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: didState.state="action"

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("completeAggregationCohort");
        didStateAction.putAdditionalProperty("aggregationCohort", aggregationCohort.getId());

        // REGISTRATION STATE: didRegistrationMetadata

        if (bitcoinConnection != null) didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());
        if (ipfsConnection != null) didRegistrationMetadata.putAll(ipfsConnection.getMetadata());
        if (aggregationCohort != null) didRegistrationMetadata.putAll(aggregationCohort.getMetadata());

        // create() state

        CreateState createState = new CreateState();
        createState.setDidState(didStateAction);
        createState.setDidRegistrationMetadata(didRegistrationMetadata);
        createState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return createState;
    }

    public static CreateState transitionToFinished(BitcoinConnection bitcoinConnection, IPFSConnection ipfsConnection, AggregationCohort aggregationCohort, byte[] initialKey, DIDDocument genesisDocument, DID did, MerkleNode merkleNodeGenesisDocument, Map<String, Object> didRegistrationMetadata, Map<String, Object> didDocumentMetadata) {

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

        if (bitcoinConnection != null) didRegistrationMetadata.putAll(bitcoinConnection.getMetadata());
        if (ipfsConnection != null) didRegistrationMetadata.putAll(ipfsConnection.getMetadata());
        if (aggregationCohort != null) didRegistrationMetadata.putAll(aggregationCohort.getMetadata());

        // REGISTRATION STATE: didDocumentMetadata

        if (initialKey != null) didDocumentMetadata.put("initialKey", Hex.encodeHexString(initialKey));
        if (genesisDocument != null) didDocumentMetadata.put("genesisDocument", genesisDocument.toMap());
        if (merkleNodeGenesisDocument != null) didDocumentMetadata.put("genesisDocumentCid", merkleNodeGenesisDocument.hash.toString());

        // create() state

        CreateState createState = new CreateState();
        createState.setDidState(didStateFinished);
        createState.setDidRegistrationMetadata(didRegistrationMetadata);
        createState.setDidDocumentMetadata(didDocumentMetadata);

        // done

        return createState;
    }
}
