package uniregistrar.driver.did.btcr2.crud.update;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import uniregistrar.driver.did.btcr2.aggregation.AggregationCohort;

public class UpdateActionFundAddressException extends Exception {

    private final Address address;
    private final Coin minimumValue;
    private final AggregationCohort aggregationCohort;

    public UpdateActionFundAddressException(Address address, Coin minimumValue, AggregationCohort aggregationCohort) {
        this.address = address;
        this.minimumValue = minimumValue;
        this.aggregationCohort = aggregationCohort;
    }

    public Address getAddress() {
        return address;
    }

    public Coin getMinimumValue() {
        return minimumValue;
    }

    public AggregationCohort getAggregationCohort() {
        return aggregationCohort;
    }
}
