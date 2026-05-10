package uniregistrar.driver.did.btcr2.crud.update;

import com.danubetech.btc.connection.BitcoinConnection;
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

public class UpdateProcessUtxoSingletonSignPayloads {

    private static final Coin BITCOIN_FEE = Coin.valueOf(100);

    private static final Logger log = LoggerFactory.getLogger(UpdateProcessUtxoSingletonSignPayloads.class);

    private IPFSConnection ipfsConnection;

    public UpdateProcessUtxoSingletonSignPayloads(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }

    public UpdateProcessUtxoSingletonSignPayloadsResult update(BitcoinConnection bitcoinConnection, BTCR2Update update, Transaction unsignedBeaconSignal, ECKey updateECKey, List<byte[]> utxoSingletonSignatures) throws RegistrationException {

        // The Beacon Signal is signed by the private key that controls the Beacon Address

        Transaction beaconSignal = unsignedBeaconSignal;

        for (int i=0; i<beaconSignal.getInputs().size(); i++) {
            TransactionInput transactionInput = beaconSignal.getInput(i);
            byte[] utxoSingletonSignature = utxoSingletonSignatures.get(i);
            byte[] r = new byte[32];
            byte[] s = new byte[32];
            System.arraycopy(utxoSingletonSignature, 0, r, 0, r.length);
            System.arraycopy(utxoSingletonSignature, 32, s, 0, s.length);
            ECKey.ECDSASignature signature = new ECKey.ECDSASignature(new BigInteger(1, r), new BigInteger(1, s));
            TransactionSignature transactionSignature = new TransactionSignature(signature, Transaction.SigHash.ALL, false);
            TransactionInput signedTransactionInput = transactionInput.withScriptSig(ScriptBuilder.createInputScript(transactionSignature, updateECKey));
            beaconSignal.replaceInput(i, signedTransactionInput);
        }
        if (log.isDebugEnabled()) log.debug("beaconSignal after signing: {}", beaconSignal);

        // and broadcast to the Bitcoin network.

        byte[] beaconSignalBytes = beaconSignal.serialize();
        if (log.isDebugEnabled()) log.debug("Broadcasting beacon signal: " + Hex.encodeHexString(beaconSignalBytes));
        String txId = bitcoinConnection.broadcastRawTransaction(beaconSignalBytes);
        if (log.isDebugEnabled()) log.debug("Transaction from beacon signal result: " + txId);

        // result

        UpdateProcessUtxoSingletonSignPayloadsResult updateProcessUtxoSingletonSignPayloadsResult = new UpdateProcessUtxoSingletonSignPayloadsResult(txId, update);
        if (log.isDebugEnabled()) log.debug("Update: " + updateProcessUtxoSingletonSignPayloadsResult);
        return updateProcessUtxoSingletonSignPayloadsResult;
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
