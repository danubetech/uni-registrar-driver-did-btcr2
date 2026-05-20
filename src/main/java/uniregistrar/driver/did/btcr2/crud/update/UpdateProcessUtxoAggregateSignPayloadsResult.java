package uniregistrar.driver.did.btcr2.crud.update;

import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;
import uniregistrar.driver.did.btcr2.data.CASAnnouncement;
import uniregistrar.driver.did.btcr2.data.SmtProof;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;

public record UpdateProcessUtxoAggregateSignPayloadsResult(String broadcastRawTransactionId, BTCR2Update update, CASAnnouncement casAnnouncement, SmtProof smtProof, AggregationCohort aggregationCohort) {
}
