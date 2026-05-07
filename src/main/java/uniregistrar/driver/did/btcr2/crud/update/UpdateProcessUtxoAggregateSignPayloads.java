package uniregistrar.driver.did.btcr2.crud.update;

import com.danubetech.btc.connection.BitcoinConnection;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import jakarta.json.JsonPatch;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.ScriptBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;

import java.math.BigInteger;
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

    public UpdateProcessUtxoAggregateSignPayloadsResult update(BitcoinConnection bitcoinConnection, DID did, DIDDocument didSourceDocument, Integer targetVersionId, JsonPatch jsonPatches, BTCR2Update btcr2Update, Transaction unsignedBeaconSignal, ECKey updateECKey, List<byte[]> utxoAggregateSigningResponseSignatures, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // The Beacon Signal is signed by the private key that controls the Beacon Address

        Transaction beaconSignal = unsignedBeaconSignal;

        for (int i = 0; i<beaconSignal.getInputs().size(); i++) {
            TransactionInput transactionInput = beaconSignal.getInput(i);
            byte[] utxoAggregateSigningResponseSignature = utxoAggregateSigningResponseSignatures.get(i);
            byte[] r = new byte[32];
            byte[] s = new byte[32];
            System.arraycopy(utxoAggregateSigningResponseSignature, 0, r, 0, r.length);
            System.arraycopy(utxoAggregateSigningResponseSignature, 32, s, 0, s.length);
            ECKey.ECDSASignature signature = new ECKey.ECDSASignature(new BigInteger(1, r), new BigInteger(1, s));
            TransactionSignature transactionSignature = new TransactionSignature(signature, Transaction.SigHash.ALL, false);
            TransactionInput signedTransactionInput = transactionInput.withScriptSig(ScriptBuilder.createInputScript(transactionSignature, updateECKey));
            beaconSignal.replaceInput(i, signedTransactionInput);
        }
        if (log.isDebugEnabled()) log.debug("beaconSignal after signing: {}", beaconSignal);

        // and broadcast to the Bitcoin network.

        byte[] beaconSignalBytes = beaconSignal.serialize();
        if (log.isDebugEnabled()) log.debug("Broadcasting beacon signal: " + Hex.encodeHexString(beaconSignalBytes));
        bitcoinConnection.broadcastRawTransaction(beaconSignalBytes);

        // result

        UpdateProcessUtxoAggregateSignPayloadsResult updateProcessUtxoAggregateSignPayloads = new UpdateProcessUtxoAggregateSignPayloadsResult(btcr2Update, null);
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
