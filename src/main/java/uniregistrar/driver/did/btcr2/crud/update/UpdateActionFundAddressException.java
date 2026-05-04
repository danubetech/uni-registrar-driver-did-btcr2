package uniregistrar.driver.did.btcr2.crud.update;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;

public class UpdateActionFundAddressException extends Exception {

    private final Address address;
    private final Coin minimumValue;

    public UpdateActionFundAddressException(Address address, Coin minimumValue) {
        this.address = address;
        this.minimumValue = minimumValue;
    }

    public Address getAddress() {
        return address;
    }

    public Coin getMinimumValue() {
        return minimumValue;
    }
}
