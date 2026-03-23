package uniregistrar.driver.did.btcr2.data.records;

import uniresolver.driver.did.btcr2.connections.bitcoin.records.Tx;

public record BeaconSignal(
        String beaconId,
        String beaconType,
        Tx tx,
        Integer blockheight,
        Long blocktime) {
}
