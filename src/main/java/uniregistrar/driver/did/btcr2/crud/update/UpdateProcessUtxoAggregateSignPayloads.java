package uniregistrar.driver.did.btcr2.crud.update;

import com.danubetech.btc.connection.BitcoinConnection;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.ScriptBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;
import uniregistrar.driver.did.btcr2.aggregation.AggregationService;
import uniregistrar.driver.did.btcr2.data.json.CASAnnouncement;
import uniregistrar.driver.did.btcr2.data.json.SMTProof;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.util.BytesArray;

import java.math.BigInteger;
import java.net.URI;
import java.util.List;
import java.util.Map;

/*
 * Update
 * See https://dcdpr.github.io/did-btcr2/operations/update.html
 */

public class UpdateProcessUtxoAggregateSignPayloads {

    private static final String BTCR2_UNSIGNED_UPDATE_TEMPLATE =
            """
                {
                  "@context": [
                    "https://btcr2.dev/context/v1",
                    "https://w3id.org/json-ld-patch/v1",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/security/data-integrity/v2"
                  ],
                  "patch": {{array-of-patches}},
                  "sourceHash": "{{source-hash}}",
                  "targetHash": "{{target-hash}}",
                  "targetVersionId": {{target-version-id}}
                }
            """;

    private static final String DATA_INTEGRITY_TEMPLATE =
            """
                {
                  "@context": [
                    "https://btcr2.dev/context/v1",
                    "https://w3id.org/json-ld-patch/v1",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/security/data-integrity/v2"
                  ],
                  "type": "DataIntegrityProof",
                  "cryptosuite": "bip340-jcs-2025",
                  "verificationMethod": "{{ verification-method }}",
                  "proofPurpose": "capabilityInvocation",
                  "capability": "{{ capability }}",
                  "capabilityAction": "Write"
                }
            """;

    private static final Coin BITCOIN_FEE = Coin.valueOf(100);

    private static final Logger log = LoggerFactory.getLogger(UpdateProcessUtxoAggregateSignPayloads.class);

    private IPFSConnection ipfsConnection;

    public UpdateProcessUtxoAggregateSignPayloads(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }

    public UpdateProcessUtxoAggregateSignPayloadsResult update(BitcoinConnection bitcoinConnection, DID did, DIDDocument didSourceDocument, BTCR2Update update, URI verificationMethodId, Transaction unsignedBeaconSignal, String aggregationCohortId, List<byte[]> utxoAggregateSignatures, Map<String, Object> didDocumentMetadata) throws RegistrationException, UpdateActionCompleteAggregationSignaturesException {

        // find aggregation cohort

        AggregationCohort aggregationCohort = AggregationService.getAggregationCohort(aggregationCohortId);
        if (aggregationCohort == null) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot find aggregation cohort " + aggregationCohortId);
        }

        // Each confirmation contains a partial signature.

        int participantIndex = aggregationCohort.findParticipantIndexByVerificationMethod(didSourceDocument, verificationMethodId);

        // Each confirmation contains a partial signature.

        aggregationCohort.setUtxoAggregateSignatures(participantIndex, utxoAggregateSignatures.stream().map(BytesArray::bytesArray).toList());

        // After the Aggregation Service receives confirmation of the Beacon Signal from all Aggregation Participants within the Aggregation Cohort

        if (! aggregationCohort.isSignaturesCompleted()) {
            // next state
            throw new UpdateActionCompleteAggregationSignaturesException(aggregationCohort);
        }

        // it finalizes the signature on the Beacon Signal.

        if (! aggregationCohort.isSignaturesAggregated()) {
            aggregationCohort.aggregateSignatures(bitcoinConnection);
        }

        // The result is a signed Bitcoin transaction.

        Transaction beaconSignal = unsignedBeaconSignal;

        for (int i=0; i<beaconSignal.getInputs().size(); i++) {
            TransactionInput transactionInput = beaconSignal.getInput(i);
            byte[] musig2AggregatedSignature = aggregationCohort.getMusig2AggregatedSignatures().get(i).bytes();
            TransactionWitness transactionWitness = TransactionWitness.of(musig2AggregatedSignature);
            TransactionInput signedTransactionInput = transactionInput.withWitness(transactionWitness).withoutScriptBytes();
            beaconSignal.replaceInput(i, signedTransactionInput);
        }
        if (log.isDebugEnabled()) log.debug("beaconSignal after signing: {}", beaconSignal);

        // The Aggregation Service then broadcasts this transaction onto the Bitcoin network.

        byte[] beaconSignalBytes = beaconSignal.serialize();
        if (log.isDebugEnabled()) log.debug("Broadcasting beacon signal: " + Hex.encodeHexString(beaconSignalBytes));
        String broadcastResult = bitcoinConnection.broadcastRawTransaction(beaconSignalBytes);
        if (log.isDebugEnabled()) log.debug("Broadcasting beacon signal result: " + broadcastResult);

        // result

        CASAnnouncement casAnnouncement = aggregationCohort.generateCasAnnouncement();
        SMTProof smtProof = aggregationCohort.generateSmtProof();

        UpdateProcessUtxoAggregateSignPayloadsResult updateProcessUtxoAggregateSignPayloads = new UpdateProcessUtxoAggregateSignPayloadsResult(update, casAnnouncement, smtProof, aggregationCohort);
        if (log.isDebugEnabled()) log.debug("Update: " + updateProcessUtxoAggregateSignPayloads);
        return updateProcessUtxoAggregateSignPayloads;
    }

    /*
     * Getters and setters
     */

    public IPFSConnection getIpfsConnection() {
        return ipfsConnection;
    }

    public void setIpfsConnection(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }
}
