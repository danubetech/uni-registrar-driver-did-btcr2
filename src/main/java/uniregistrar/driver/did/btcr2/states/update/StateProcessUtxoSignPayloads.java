package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.BitcoinConnector;
import com.danubetech.btc.syntax.IdentifierComponents;
import com.danubetech.keyformats.JWK_to_PublicKey;
import com.danubetech.keyformats.PublicKeyBytes;
import com.danubetech.keyformats.jose.JWK;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.parser.ParserException;
import io.ipfs.multibase.Multibase;
import jakarta.json.Json;
import jakarta.json.JsonPatch;
import org.bitcoinj.crypto.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.crud.update.Update;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUtxoSignPayloadsResult;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierDecoding;
import uniregistrar.driver.did.btcr2.util.MultiCodecUtil;
import uniregistrar.openapi.model.*;

import java.util.*;

public class StateProcessUtxoSignPayloads {

    private static final Logger log = LoggerFactory.getLogger(StateProcessUtxoSignPayloads.class);

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

        byte[] btcr2UpdateAnnouncement = updateJob.btcr2UpdateAnnouncement() == null ? null : Base64.getDecoder().decode(updateJob.btcr2UpdateAnnouncement());
        if (btcr2UpdateAnnouncement == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'btcr2UpdateAnnouncement' in jobId");

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
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Verification method public data not found");
        }

        ECKey updateECKey = null;
        try {
            if (updateVerificationMethodPublicData.getPublicKeyJwk() != null) {
                updateECKey = JWK_to_PublicKey.JWK_to_secp256k1PublicKey(JWK.fromMap(updateVerificationMethodPublicData.getPublicKeyJwk()));
            } else if (updateVerificationMethodPublicData.getPublicKeyMultibase() != null) {
                updateECKey = PublicKeyBytes.bytes_to_secp256k1PublicKey(MultiCodecUtil.removeMulticodec(Multibase.decode(updateVerificationMethodPublicData.getPublicKeyMultibase()), MultiCodecUtil.MULTICODEC_SECP256K1_PUB));
            }
        } catch (Exception ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot construct update public key from verification method public data: "+ ex.getMessage(), ex);
        }

        if (updateECKey == null) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot find update public key from verification method public data: "+ updateVerificationMethodPublicData);
        }

        // read signing responses

        Map<String, SigningResponse> signingResponses = requestSecret == null ? null : requestSecret.getSigningResponse();
        List<SigningResponse> utxoSigningResponses = signingResponses == null ? null : signingResponses.entrySet().stream().filter(signingResponseEntry -> signingResponseEntry.getKey().startsWith("utxo")).map(Map.Entry::getValue).toList();

        if (utxoSigningResponses == null) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Signing responses 'utxo*' not found");
        }

        List<byte[]> utxoSigningResponseSignatures = utxoSigningResponses.stream().map(SigningResponse::getSignature).map(signature -> Base64.getDecoder().decode(signature)).toList();

        // update()

        UpdateProcessUtxoSignPayloadsResult updateProcessUtxoSignPayloadsResult = update.updateProcessUtxoSignPayloads(bitcoinConnection, didSourceDocument, targetVersionId, jsonPatches, btcr2UpdateAnnouncement, updateECKey, utxoSigningResponseSignatures, didDocumentMetadata);

        // next state

        return TransitionProcessUtxoSignPayloads.transitionToFinished(bitcoinConnection, btcr2Update, didRegistrationMetadata, didDocumentMetadata);
    }
}
