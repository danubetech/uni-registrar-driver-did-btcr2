package uniregistrar.driver.did.btcr2.crud.update;

import org.bitcoinj.core.Transaction;

import java.util.List;

public record UpdateProcessUpdateSignPayloadResult(Transaction btcr2Transaction, List<byte[]> utxoSignPayloads) {
}
