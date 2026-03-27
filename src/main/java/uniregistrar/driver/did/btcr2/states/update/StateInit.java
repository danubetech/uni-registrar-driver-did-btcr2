package uniregistrar.driver.did.btcr2.states.update;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.DIDDocumentV1_1;
import foundation.identity.did.parser.ParserException;
import jakarta.json.Json;
import jakarta.json.JsonPatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnection;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.crud.update.Update;
import uniregistrar.driver.did.btcr2.data.records.IdentifierComponents;
import uniregistrar.driver.did.btcr2.job.Job;
import uniregistrar.driver.did.btcr2.job.JobRegistry;
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierDecoding;
import uniregistrar.openapi.model.SigningResponse;
import uniregistrar.openapi.model.UpdateRequest;
import uniregistrar.openapi.model.UpdateState;
import uniregistrar.openapi.model.VerificationMethodPublicData;

import java.util.*;

public class StateInit {

    private static final Logger log = LoggerFactory.getLogger(StateInit.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .defaultPropertyInclusion(JsonInclude.Value.ALL_NON_NULL)
            .build();

    public static final int STATE = 0;

    public static UpdateState update(JobRegistry jobRegistry, Job job, UpdateRequest updateRequest, Update update, BitcoinConnector bitcoinConnector) throws RegistrationException {

        // prepare didRegistrationMetadata and didDocumentMetadata

        Map<String, Object> didRegistrationMetadata = new LinkedHashMap<>();
        Map<String, Object> didDocumentMetadata = new LinkedHashMap<>();

        // read input DID

        DID did;
        try {
            did = DID.fromString(updateRequest.getDid());
        } catch (ParserException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid DID: " + updateRequest.getDid());
        }

        IdentifierComponents identifierComponents = DidBtcr2IdentifierDecoding.didBtcr2IdentifierDecoding(did);

        // read input DID documents

        List<DIDDocument> didDocument = updateRequest.getDidDocument().stream().map(x -> jsonMapper.convertValue(x, DIDDocument.class)).toList();

        // read input DID document update operations

        List<JsonPatch> jsonPatches = new ArrayList<>();
        if (updateRequest.getDidDocumentOperation() != null && updateRequest.getDidDocument() != null) {
            for (int i=0; i<updateRequest.getDidDocumentOperation().size(); i++) {
                String didDocumentOperation = updateRequest.getDidDocumentOperation().get(i);
                DIDDocumentV1_1 didDocument = jsonMapper.convertValue(updateRequest.getDidDocument().get(i), DIDDocumentV1_1.class);
                if (! "patchDidDocument".equals(didDocumentOperation)) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Unsupported DID document operation: " + didDocumentOperation);
                JsonPatch jsonPatch = Json.createPatch(Json.createArrayBuilder(Collections.singletonList(didDocument.getJsonObject())).build());
                jsonPatches.add(jsonPatch);
            }
        }

        // read targetVersionId option

        Integer targetVersionId = updateRequest.getOptions() == null ? null : (Integer) updateRequest.getOptions().getAdditionalProperties().get("targetVersionId");

        // read verification method public data and signing response

        VerificationMethodPublicData verificationMethodPublicData = null;
        SigningResponse signingResponse = null;

        if (updateRequest.getSecret() != null && updateRequest.getSecret().getVerificationMethod() != null && ! updateRequest.getSecret().getVerificationMethod().isEmpty()) verificationMethodPublicData = updateRequest.getSecret().getVerificationMethod().getFirst().getVerificationMethodPublicData();
        if (updateRequest.getSecret() != null && updateRequest.getSecret().getSigningResponse() != null && ! updateRequest.getSecret().getSigningResponse().isEmpty()) signingResponse = updateRequest.getSecret().getSigningResponse().get("didUpdate");

        // find Bitcoin connection

        BitcoinConnection bitcoinConnection = bitcoinConnector.getBitcoinConnection(identifierComponents.network());
        if (bitcoinConnection == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Unknown network: " + identifierComponents.network());

        // prepare didSourceDocument

        DIDDocumentV1_1 didSourceDocument = (DIDDocumentV1_1) didDocument;

        // update()

        try {
            update.update(didSourceDocument, jsonPatches, targetVersionId, verificationMethodPublicData, signingResponse, didDocumentMetadata);
        } catch (Update.GetVerificationMethodException ex) {

            // next state

            return TransitionInit.transitionToInitGetVerificationMethod(bitcoinConnection, didRegistrationMetadata, didDocumentMetadata);
        } catch (Update.SignPayloadException ex) {

            // next state

            return TransitionInit.transitionToSignPayload(bitcoinConnection, verificationMethodPublicData, didRegistrationMetadata, didDocumentMetadata);
        }

        // next state

        return TransitionInit.transitionToFinished(jobRegistry, job, bitcoinConnection, did, didRegistrationMetadata, didDocumentMetadata);
    }
}
