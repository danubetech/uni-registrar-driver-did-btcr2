package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.BitcoinConnector;
import com.danubetech.btc.syntax.IdentifierComponents;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.parser.ParserException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.crud.update.UpdateActionCompleteAggregationUpdatesException;
import uniregistrar.driver.did.btcr2.crud.update.UpdateActionFundAddressException;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUpdateSignPayload;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUpdateSignPayloadResult;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierDecoding;
import uniregistrar.openapi.model.RequestSecret;
import uniregistrar.openapi.model.SigningResponse;
import uniregistrar.openapi.model.UpdateRequest;
import uniregistrar.openapi.model.UpdateState;

import java.net.URI;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public class StateProcessUpdateSignPayload {

    private static final Logger log = LoggerFactory.getLogger(StateProcessUpdateSignPayload.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .defaultPropertyInclusion(JsonInclude.Value.ALL_NON_NULL)
            .build();

    public static UpdateState update(UpdateJob updateJob, UpdateRequest updateRequest, UpdateProcessUpdateSignPayload updateProcessUpdateSignPayload, BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) throws RegistrationException {

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

        // read job

        BTCR2Update btcr2Update = updateJob.btcr2Update() == null ? null : BTCR2Update.fromJson(updateJob.btcr2Update());
        if (btcr2Update == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'btcr2Update' in jobId");

        byte[] updateSignPayload = updateJob.updateSignPayload() == null ? null : Base64.getDecoder().decode(updateJob.updateSignPayload());
        if (updateSignPayload == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'updateSignPayload' in jobId");

        // read options

        DIDDocument didSourceDocument = updateRequest.getOptions() == null || updateRequest.getOptions().getAdditionalProperty("didSourceDocument") == null ? null : DIDDocument.fromJsonObject((Map<String, Object>) updateRequest.getOptions().getAdditionalProperty("didSourceDocument"));
        URI beaconServiceId = updateRequest.getOptions() == null ? null : (updateRequest.getOptions().getAdditionalProperty("beaconServiceId") instanceof String beaconServiceIdString ? URI.create(beaconServiceIdString) : null);
        String beaconServiceType = updateRequest.getOptions() == null ? null : (updateRequest.getOptions().getAdditionalProperty("beaconServiceType") instanceof String beaconServiceTypeString ? beaconServiceTypeString : null);
        if (didSourceDocument == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'didSourceDocument' option");

        // read signing response

        RequestSecret requestSecret = updateRequest.getSecret();
        Map<String, SigningResponse> signingResponses = requestSecret == null ? null : requestSecret.getSigningResponse();
        SigningResponse updateSigningResponse = signingResponses == null ? null : signingResponses.get("update");

        if (updateSigningResponse == null) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Signing response 'update' not found: " + updateSigningResponse);
        }
        if (updateSigningResponse.getKid() == null) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Signing response 'update' has no 'kid'");
        }

        URI verificationMethodId = URI.create(updateSigningResponse.getKid());
        byte[] updateSignature = Base64.getDecoder().decode(updateSigningResponse.getSignature());

        // update()

        UpdateProcessUpdateSignPayloadResult updateProcessUpdateSignPayloadResult;
        try {
            updateProcessUpdateSignPayloadResult = updateProcessUpdateSignPayload.update(bitcoinConnection, did, btcr2Update, verificationMethodId, didSourceDocument, beaconServiceId, beaconServiceType, updateSignature, didDocumentMetadata);
        } catch (UpdateActionFundAddressException ex) {
            // next state
            return TransitionProcessUpdateSignPayload.transitionToUpdateSignPayloadFundAddress(bitcoinConnection, ipfsConnection, btcr2Update, updateSignPayload, ex.getAddress(), ex.getMinimumValue(), didRegistrationMetadata, didDocumentMetadata);
        } catch (UpdateActionCompleteAggregationUpdatesException ex) {
            // next state
            return TransitionProcessUpdateSignPayload.transitionToUpdateSignPayloadCompleteAggregationUpdates(bitcoinConnection, ipfsConnection, btcr2Update, updateSignPayload, ex.getAggregationCohort(), didRegistrationMetadata, didDocumentMetadata);
        }

        // next state

        if (updateProcessUpdateSignPayloadResult.utxoSingletonSignPayloads() != null) {
            return TransitionProcessUpdateSignPayload.transitionToUtxoSingletonSignPayloads(bitcoinConnection, ipfsConnection, updateProcessUpdateSignPayloadResult.btcr2Update(), updateProcessUpdateSignPayloadResult.unsignedBeaconSignal(), updateProcessUpdateSignPayloadResult.utxoSingletonSignPayloads(), didRegistrationMetadata, didDocumentMetadata);
        }
        if (updateProcessUpdateSignPayloadResult.utxoAggregateSignPayloads() != null) {
            return TransitionProcessUpdateSignPayload.transitionToUtxoAggregateSignPayloads(bitcoinConnection, ipfsConnection, updateProcessUpdateSignPayloadResult.btcr2Update(), updateProcessUpdateSignPayloadResult.unsignedBeaconSignal(), updateProcessUpdateSignPayloadResult.utxoAggregateSignPayloads(), updateProcessUpdateSignPayloadResult.aggregationCohort(), didRegistrationMetadata, didDocumentMetadata);
        }
        throw new IllegalArgumentException("Invalid result: " + updateProcessUpdateSignPayloadResult);
    }
}
