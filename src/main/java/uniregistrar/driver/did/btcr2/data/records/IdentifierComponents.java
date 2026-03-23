package uniregistrar.driver.did.btcr2.data.records;

import uniregistrar.driver.did.btcr2.Network;

public record IdentifierComponents(
        int version,
        Network network,
        byte[] genesisBytes,
        GenesisBytesType genesisBytesType) {
}
