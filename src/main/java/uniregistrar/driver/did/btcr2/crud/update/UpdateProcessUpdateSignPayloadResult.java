package uniregistrar.driver.did.btcr2.crud.update;

import org.bitcoinj.core.Transaction;
import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;

import java.util.List;

public record UpdateProcessUpdateSignPayloadResult(BTCR2Update btcr2Update, Transaction unsignedBeaconSignal, List<byte[]> utxoSingletonSignPayloads, List<byte[]> utxoAggregateSignPayloads, AggregationCohort aggregationCohort) {
}
