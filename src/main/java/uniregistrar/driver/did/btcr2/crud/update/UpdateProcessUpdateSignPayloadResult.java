package uniregistrar.driver.did.btcr2.crud.update;

import org.bitcoinj.core.Transaction;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;

import java.util.List;

public record UpdateProcessUpdateSignPayloadResult(BTCR2Update btcr2Update, Transaction btcr2Transaction, List<byte[]> utxoSignPayloads) {
}
