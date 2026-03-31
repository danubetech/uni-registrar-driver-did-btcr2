package uniregistrar.driver.did.btcr2.crud.update;

import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;

import java.util.List;
import java.util.stream.IntStream;

public class ActionUtxoSignPayloadsException extends Exception {

    private final List<byte[]> payloads;

    public ActionUtxoSignPayloadsException(List<byte[]> payloads) {
        this.payloads = payloads;
    }

    public static ActionUtxoSignPayloadsException create(Transaction transaction) {
        List<byte[]> payloads = IntStream.range(0, transaction.getInputs().size())
                .mapToObj(i -> transaction.hashForSignature(
                        i,
                        transaction.getInput(i).getScriptBytes(),
                        Transaction.SigHash.ALL,
                        false))
                .map(Sha256Hash::getBytes)
                .toList();
        return new ActionUtxoSignPayloadsException(payloads);
    }

    public List<byte[]> getPayloads() {
        return payloads;
    }
}
