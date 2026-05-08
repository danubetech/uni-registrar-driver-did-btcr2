package uniregistrar.driver.did.btcr2.crud.update;

import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;

public class UpdateActionCompleteAggregationSignaturesException extends Exception {

    private final AggregationCohort aggregationCohort;

    public UpdateActionCompleteAggregationSignaturesException(AggregationCohort aggregationCohort) {
        this.aggregationCohort = aggregationCohort;
    }

    public AggregationCohort getAggregationCohort() {
        return aggregationCohort;
    }
}
