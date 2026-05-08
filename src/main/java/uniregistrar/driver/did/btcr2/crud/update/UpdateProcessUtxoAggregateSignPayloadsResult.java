package uniregistrar.driver.did.btcr2.crud.update;

import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;

public record UpdateProcessUtxoAggregateSignPayloadsResult(BTCR2Update update, AggregationCohort aggregationCohort) {
}
