package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.BitcoinConnector;
import com.danubetech.btc.syntax.IdentifierComponents;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.parser.ParserException;
import jakarta.json.Json;
import jakarta.json.JsonPatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.crud.update.Update;
import uniregistrar.driver.did.btcr2.crud.update.UpdateActionFundAddressException;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUpdateSignPayloadResult;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierDecoding;
import uniregistrar.openapi.model.RequestSecret;
import uniregistrar.openapi.model.SigningResponse;
import uniregistrar.openapi.model.UpdateRequest;
import uniregistrar.openapi.model.UpdateState;

import java.net.URI;
import java.util.*;

public class StateProcessUpdateSignPayload {

    private static final Logger log = LoggerFactory.getLogger(StateProcessUpdateSignPayload.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .defaultPropertyInclusion(JsonInclude.Value.ALL_NON_NULL)
            .build();

    public static UpdateState update(UpdateJob updateJob, UpdateRequest updateRequest, Update update, BitcoinConnector bitcoinConnector) throws RegistrationException {

        // prepare didRegistrationMetadata and didDocumentMetadata

        Map<String, Object> didRegistrationMetadata = new LinkedHashMap<>();
        Map<String, Object> didDocumentMetadata = new LinkedHashMap<>();

        // read job

        BTCR2Update btcr2Update = updateJob.btcr2Update() == null ? null : BTCR2Update.fromJson(updateJob.btcr2Update());
        if (btcr2Update == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'btcr2Update' in jobId");

        byte[] updateSignPayload = updateJob.updateSignPayload() == null ? null : Base64.getDecoder().decode(updateJob.updateSignPayload());
        if (updateSignPayload == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'updateSignPayload' in jobId");

        // read input DID

        DID did;
        try {
            did = DID.fromString(updateRequest.getDid());
        } catch (ParserException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid DID: " + updateRequest.getDid());
        }

        IdentifierComponents identifierComponents = DidBtcr2IdentifierDecoding.didBtcr2IdentifierDecoding(did);

        // find Bitcoin connection

        BitcoinConnection bitcoinConnection = bitcoinConnector.getBitcoinConnection(identifierComponents.network());
        if (bitcoinConnection == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Unknown network: " + identifierComponents.network());

        // read didSourceDocument and targetVersionId options

        DIDDocument didSourceDocument = updateRequest.getOptions() == null || updateRequest.getOptions().getAdditionalProperty("didSourceDocument") == null ? null : DIDDocument.fromJsonObject((Map<String, Object>) updateRequest.getOptions().getAdditionalProperty("didSourceDocument"));
        Integer targetVersionId = updateRequest.getOptions() == null ? null : (Integer) updateRequest.getOptions().getAdditionalProperty("targetVersionId");
        if (didSourceDocument == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'didSourceDocument' option");
        if (targetVersionId == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'targetVersionId' option");

        // read input DID document operations and DID documents

        List<String> didDocumentOperations = updateRequest.getDidDocumentOperation() == null ? Collections.emptyList() : updateRequest.getDidDocumentOperation();;
        List<DIDDocument> didDocuments = updateRequest.getDidDocument() == null ? Collections.emptyList() : updateRequest.getDidDocument().stream().map(x -> jsonMapper.convertValue(x, DIDDocument.class)).toList();

        // read input DID document update operations

        List<Map<String, Object>> jsonPatchesObjects = new LinkedList<>();
        for (int i=0; i<didDocumentOperations.size(); i++) {
            String didDocumentOperation = didDocumentOperations.get(i);
            DIDDocument didDocument = didDocuments.get(i);
            if (! "patchDidDocument".equals(didDocumentOperation)) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Unsupported DID document operation: " + didDocumentOperation);
            jsonPatchesObjects.add(didDocument.getJsonObject());
        }
        JsonPatch jsonPatches = Json.createPatch(Json.createArrayBuilder(jsonPatchesObjects).build());

        // read signing response

        RequestSecret requestSecret = updateRequest.getSecret();
        Map<String, SigningResponse> signingResponses = requestSecret == null ? null : requestSecret.getSigningResponse();
        SigningResponse updateSigningResponse = signingResponses == null ? null : signingResponses.get("update");

        if (updateSigningResponse == null || updateSigningResponse.getKid() == null) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Signing response 'update' not found");
        }

        URI verificationMethodId = URI.create(updateSigningResponse.getKid());
        byte[] updateSigningResponseSignature = Base64.getDecoder().decode(updateSigningResponse.getSignature());

        // update()

        UpdateProcessUpdateSignPayloadResult updateProcessUpdateSignPayloadResult;
        try {
            updateProcessUpdateSignPayloadResult = update.updateProcessUpdateSignPayload(bitcoinConnection, didSourceDocument, targetVersionId, jsonPatches, btcr2Update, verificationMethodId, updateSigningResponseSignature, didDocumentMetadata);
        } catch (UpdateActionFundAddressException ex) {
            // next state
            return TransitionProcessUpdateSignPayload.transitionToUpdateSignPayloadFundAddress(bitcoinConnection, ex.getAddress(), ex.getMinimumValue(), btcr2Update, updateSignPayload, didRegistrationMetadata, didDocumentMetadata);
        }

        // next state

        return TransitionProcessUpdateSignPayload.transitionToUtxoSignPayloads(bitcoinConnection, btcr2Update, updateProcessUpdateSignPayloadResult.btcr2Transaction(), updateProcessUpdateSignPayloadResult.utxoSignPayloads(), didRegistrationMetadata, didDocumentMetadata);
    }
}
