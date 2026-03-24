package uniregistrar.driver.did.btcr2.data.records;

import org.bitcoinj.base.Address;

public record Beacon(
        String id,
        String type,
        String serviceEndpoint,
        Address address) {
}
