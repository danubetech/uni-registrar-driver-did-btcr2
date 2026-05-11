package uniregistrar.driver.did.btcr2.states.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.btc.connection.BitcoinConnector;
import com.danubetech.btc.syntax.IdentifierComponents;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.json.JsonMapper;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.parser.ParserException;
import io.ipfs.api.AddArgs;
import io.ipfs.api.MerkleNode;
import io.ipfs.api.NamedStreamable;
import org.bitcoinj.core.Transaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.algorithms.JSONDocumentHashing;
import uniregistrar.driver.did.btcr2.crud.update.UpdateActionCompleteAggregationSignaturesException;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUtxoAggregateSignPayloads;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUtxoAggregateSignPayloadsResult;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierDecoding;
import uniregistrar.openapi.model.RequestSecret;
import uniregistrar.openapi.model.SigningResponse;
import uniregistrar.openapi.model.UpdateRequest;
import uniregistrar.openapi.model.UpdateState;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class StateProcessUtxoAggregateSignPayloads {

    private static final Logger log = LoggerFactory.getLogger(StateProcessUtxoAggregateSignPayloads.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .defaultPropertyInclusion(JsonInclude.Value.ALL_NON_NULL)
            .build();

    public static UpdateState update(UpdateJob updateJob, UpdateRequest updateRequest, UpdateProcessUtxoAggregateSignPayloads updateProcessUtxoAggregateSignPayloads, BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) throws RegistrationException {

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

        BTCR2Update update = updateJob.update() == null ? null : BTCR2Update.fromJson(updateJob.update());
        if (update == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'update' in jobId");

        Transaction unsignedBeaconSignal = updateJob.unsignedBeaconSignal() == null ? null : Transaction.read(ByteBuffer.wrap(Base64.getDecoder().decode(updateJob.unsignedBeaconSignal())));
        if (unsignedBeaconSignal == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'unsignedBeaconSignal' in jobId");

        List<byte[]> utxoAggregateSignPayloads = updateJob.utxoAggregateSignPayloads() == null ? null : updateJob.utxoAggregateSignPayloads().stream().map(x -> Base64.getDecoder().decode(x)).toList();
        if (utxoAggregateSignPayloads == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'utxoAggregateSignPayloads' in jobId");

        String aggregationCohortId = updateJob.aggregationCohortId();
        if (aggregationCohortId == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'aggregationCohortId' in jobId");

        // read options

        DIDDocument didSourceDocument = updateRequest.getOptions() == null || updateRequest.getOptions().getAdditionalProperty("didSourceDocument") == null ? null : DIDDocument.fromJsonObject((Map<String, Object>) updateRequest.getOptions().getAdditionalProperty("didSourceDocument"));
        Boolean publishToIpfs = updateRequest.getOptions() == null ? null : (updateRequest.getOptions().getAdditionalProperty("publishToIpfs") == null ? null : (Boolean) updateRequest.getOptions().getAdditionalProperty("publishToIpfs"));
        if (didSourceDocument == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Missing 'didSourceDocument' option");
        if (publishToIpfs == null) publishToIpfs = Boolean.TRUE;

        // read signing responses

        RequestSecret requestSecret = updateRequest.getSecret();
        Map<String, SigningResponse> signingResponses = requestSecret == null ? null : requestSecret.getSigningResponse();
        List<SigningResponse> utxoAggregateSigningResponses = signingResponses == null ? null : signingResponses.entrySet().stream().filter(signingResponseEntry -> signingResponseEntry.getKey().startsWith("utxoAggregate")).map(Map.Entry::getValue).toList();

        if (utxoAggregateSigningResponses == null || utxoAggregateSigningResponses.isEmpty()) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Signing responses 'utxoAggregate*' not found: " + utxoAggregateSigningResponses);
        }
        for (SigningResponse utxoAggregateSigningResponse : utxoAggregateSigningResponses) {
            if (utxoAggregateSigningResponse.getKid() == null) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Signing response 'utxoAggregate*' has no 'kid'");
        }

        List<URI> verificationMethodIds = utxoAggregateSigningResponses.stream().map(SigningResponse::getKid).map(URI::create).toList();
        List<byte[]> utxoAggregateSignatures = utxoAggregateSigningResponses.stream().map(SigningResponse::getSignature).map(signature -> Base64.getDecoder().decode(signature)).toList();

        URI verificationMethodId = verificationMethodIds.getFirst();

        if (! verificationMethodIds.stream().allMatch(verificationMethodId::equals)) throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Signing responses 'utxoAggregate*' have different 'kid's:" + verificationMethodIds);

        // update()

        UpdateProcessUtxoAggregateSignPayloadsResult updateProcessUtxoAggregateSignPayloadsResult;
        try {
            updateProcessUtxoAggregateSignPayloadsResult = updateProcessUtxoAggregateSignPayloads.update(bitcoinConnection, didSourceDocument, update, verificationMethodId, unsignedBeaconSignal, aggregationCohortId, utxoAggregateSignatures);
        } catch (UpdateActionCompleteAggregationSignaturesException ex) {
            // next state
            return TransitionProcessUtxoAggregateSignPayloads.transitionToUtxoAggregateSignPayloadsCompleteAggregationSignatures(bitcoinConnection, ipfsConnection, update, unsignedBeaconSignal, ex.getAggregationCohort(), utxoAggregateSignPayloads, didRegistrationMetadata, didDocumentMetadata);
        }

        // publish to IPFS?

        MerkleNode merkleNodeUpdate = null;
        MerkleNode merkleNodeCasAnnouncement = null;
        MerkleNode merkleNodeSmtProof = null;
        if (publishToIpfs && ipfsConnection != null && updateProcessUtxoAggregateSignPayloadsResult.update() != null) {
            try {
                byte[] ipfsPayload = JSONDocumentHashing.jsonDocumentCanonicalizing(updateProcessUtxoAggregateSignPayloadsResult.update().toJson()).getBytes(StandardCharsets.UTF_8);
                AddArgs addArgs = AddArgs.Builder.newInstance().setCidVersion(1).setRawLeaves().setHash("sha2-256").setPin().build();
                merkleNodeUpdate = ipfsConnection.getIpfs().add(new NamedStreamable.ByteArrayWrapper(ipfsPayload), addArgs).getFirst();
            } catch (IOException ex) {
                throw new RegistrationException(RegistrationException.ERROR_INTERNAL_ERROR, "Cannot publish update to IPFS: " + ex.getMessage(), ex);
            }
            if (log.isDebugEnabled()) log.debug("Published update to IPFS: " + merkleNodeUpdate.hash);
        }
        if (publishToIpfs && ipfsConnection != null && updateProcessUtxoAggregateSignPayloadsResult.casAnnouncement() != null) {
            try {
                byte[] ipfsPayload = JSONDocumentHashing.jsonDocumentCanonicalizing(updateProcessUtxoAggregateSignPayloadsResult.casAnnouncement()).getBytes(StandardCharsets.UTF_8);
                AddArgs addArgs = AddArgs.Builder.newInstance().setCidVersion(1).setRawLeaves().setHash("sha2-256").setPin().build();
                merkleNodeCasAnnouncement = ipfsConnection.getIpfs().add(new NamedStreamable.ByteArrayWrapper(ipfsPayload), addArgs).getFirst();
            } catch (IOException ex) {
                throw new RegistrationException(RegistrationException.ERROR_INTERNAL_ERROR, "Cannot publish casAnnouncement to IPFS: " + ex.getMessage(), ex);
            }
            if (log.isDebugEnabled()) log.debug("Published casAnnouncement to IPFS: " + merkleNodeCasAnnouncement.hash);
        }
        if (publishToIpfs && ipfsConnection != null && updateProcessUtxoAggregateSignPayloadsResult.smtProof() != null) {
            try {
                byte[] ipfsPayload = JSONDocumentHashing.jsonDocumentCanonicalizing(updateProcessUtxoAggregateSignPayloadsResult.smtProof().toMap()).getBytes(StandardCharsets.UTF_8);
                AddArgs addArgs = AddArgs.Builder.newInstance().setCidVersion(1).setRawLeaves().setHash("sha2-256").setPin().build();
                merkleNodeSmtProof = ipfsConnection.getIpfs().add(new NamedStreamable.ByteArrayWrapper(ipfsPayload), addArgs).getFirst();
            } catch (IOException ex) {
                throw new RegistrationException(RegistrationException.ERROR_INTERNAL_ERROR, "Cannot publish smtProof to IPFS: " + ex.getMessage(), ex);
            }
            if (log.isDebugEnabled()) log.debug("Published smtProof to IPFS: " + merkleNodeSmtProof.hash);
        }

        // next state

        return TransitionProcessUtxoAggregateSignPayloads.transitionToFinished(bitcoinConnection, ipfsConnection, updateProcessUtxoAggregateSignPayloadsResult.broadcastRawTransactionId(), updateProcessUtxoAggregateSignPayloadsResult.update(), updateProcessUtxoAggregateSignPayloadsResult.casAnnouncement(), updateProcessUtxoAggregateSignPayloadsResult.smtProof(), updateProcessUtxoAggregateSignPayloadsResult.aggregationCohort(), merkleNodeUpdate, merkleNodeCasAnnouncement, merkleNodeSmtProof, didRegistrationMetadata, didDocumentMetadata);
    }
}
