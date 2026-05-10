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
import foundation.identity.did.parser.ParserException;
import io.ipfs.api.AddArgs;
import io.ipfs.api.MerkleNode;
import io.ipfs.api.NamedStreamable;
import io.ipfs.multibase.Multibase;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.crypto.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.algorithms.JSONDocumentHashing;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUtxoSingletonSignPayloads;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUtxoSingletonSignPayloadsResult;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.driver.did.btcr2.syntax.DidBtcr2IdentifierDecoding;
import uniregistrar.driver.did.btcr2.util.MultiCodecUtil;
import uniregistrar.openapi.model.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class StateProcessUtxoSingletonSignPayloads {

    private static final Logger log = LoggerFactory.getLogger(StateProcessUtxoSingletonSignPayloads.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder()
            .defaultPropertyInclusion(JsonInclude.Value.ALL_NON_NULL)
            .build();

    public static UpdateState update(UpdateJob updateJob, UpdateRequest updateRequest, UpdateProcessUtxoSingletonSignPayloads updateProcessUtxoSingletonSignPayloads, BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) throws RegistrationException {

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

        // read options

        Boolean publishToIpfs = updateRequest.getOptions() == null ? null : (updateRequest.getOptions().getAdditionalProperty("publishToIpfs") == null ? null : (Boolean) updateRequest.getOptions().getAdditionalProperty("publishToIpfs"));
        if (publishToIpfs == null) publishToIpfs = Boolean.TRUE;

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
        List<SigningResponse> utxoSingletonSigningResponses = signingResponses == null ? null : signingResponses.entrySet().stream().filter(signingResponseEntry -> signingResponseEntry.getKey().startsWith("utxoSingleton")).map(Map.Entry::getValue).toList();

        if (utxoSingletonSigningResponses == null) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Signing responses 'utxo*' not found");
        }

        List<byte[]> utxoSingletonSignatures = utxoSingletonSigningResponses.stream().map(SigningResponse::getSignature).map(signature -> Base64.getDecoder().decode(signature)).toList();

        // update()

        UpdateProcessUtxoSingletonSignPayloadsResult updateProcessUtxoSingletonSignPayloadsResult = updateProcessUtxoSingletonSignPayloads.update(bitcoinConnection, update, unsignedBeaconSignal, updateECKey, utxoSingletonSignatures, didDocumentMetadata);

        // publish to IPFS?

        MerkleNode merkleNodeUpdate = null;
        if (publishToIpfs && ipfsConnection != null && updateProcessUtxoSingletonSignPayloadsResult.update() != null) {
            try {
                byte[] ipfsPayload = JSONDocumentHashing.jsonDocumentCanonicalizing(updateProcessUtxoSingletonSignPayloadsResult.update().toJson()).getBytes(StandardCharsets.UTF_8);
                AddArgs addArgs = AddArgs.Builder.newInstance().setCidVersion(1).setRawLeaves().setHash("sha2-256").setPin().build();
                merkleNodeUpdate = ipfsConnection.getIpfs().add(new NamedStreamable.ByteArrayWrapper(ipfsPayload), addArgs).getFirst();
            } catch (IOException ex) {
                throw new RegistrationException(RegistrationException.ERROR_INTERNAL_ERROR, "Cannot publish update to IPFS: " + ex.getMessage(), ex);
            }
            if (log.isDebugEnabled()) log.debug("Published update to IPFS: " + merkleNodeUpdate.hash);
        }

        // next state

        return TransitionProcessUtxoSingletonSignPayloads.transitionToFinished(bitcoinConnection, ipfsConnection, updateProcessUtxoSingletonSignPayloadsResult.txId(), updateProcessUtxoSingletonSignPayloadsResult.update(), merkleNodeUpdate, didRegistrationMetadata, didDocumentMetadata);
    }
}
