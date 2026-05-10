package uniregistrar.driver.did.btcr2.crud.update;

import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;
import uniregistrar.driver.did.btcr2.data.json.CASAnnouncement;
import uniregistrar.driver.did.btcr2.data.json.SMTProof;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;

public record UpdateProcessUtxoAggregateSignPayloadsResult(String txId, BTCR2Update update, CASAnnouncement casAnnouncement, SMTProof smtProof, AggregationCohort aggregationCohort) {
}
