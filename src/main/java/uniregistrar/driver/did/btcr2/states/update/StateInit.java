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
import uniregistrar.driver.did.btcr2.crud.update.UpdateInitResult;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierDecoding;
import uniregistrar.openapi.model.*;

import java.net.URI;
import java.util.*;

public class StateInit {

    private static final Logger log = LoggerFactory.getLogger(StateInit.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .defaultPropertyInclusion(JsonInclude.Value.ALL_NON_NULL)
            .build();

    public static UpdateState update(UpdateJob updateJob, UpdateRequest updateRequest, Update update, BitcoinConnector bitcoinConnector) throws RegistrationException {

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

        // read verification method public data

        RequestSecret requestSecret = updateRequest.getSecret();
        List<RequestSecretVerificationMethodInner> requestSecretVerificationMethodInners = requestSecret == null ? null : requestSecret.getVerificationMethod();
        VerificationMethodPublicData updateVerificationMethodPublicData = requestSecretVerificationMethodInners == null ? null : requestSecretVerificationMethodInners.getFirst().getVerificationMethodPublicData();

        if (updateVerificationMethodPublicData == null || updateVerificationMethodPublicData.getId() == null) {
            // next state
            return TransitionInit.transitionToInitGetVerificationMethod(bitcoinConnection, didRegistrationMetadata, didDocumentMetadata);
        }

        URI verificationMethodId = URI.create(updateVerificationMethodPublicData.getId());

        // update()

        UpdateInitResult updateInitResult = update.updateInit(bitcoinConnection, didSourceDocument, targetVersionId, jsonPatches, verificationMethodId, didDocumentMetadata);

        // next state

        return TransitionInit.transitionToUpdateSignPayload(bitcoinConnection, updateInitResult.verificationMethodId(), updateInitResult.updateSignPayload(), didRegistrationMetadata, didDocumentMetadata);
    }
}
