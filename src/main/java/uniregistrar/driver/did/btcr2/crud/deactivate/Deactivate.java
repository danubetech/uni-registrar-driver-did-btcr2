package uniregistrar.driver.did.btcr2.crud.deactivate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.connections.ipfs.IPFSConnection;

import java.util.Map;

public class Deactivate {

    private static final Logger log = LoggerFactory.getLogger(Deactivate.class);

    public Deactivate(BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) {
    }

    /*
     * 7.4 Deactivate
     */

    // See https://dcdpr.github.io/did-btcr2/#deactivate
    public void deactivate(/* TODO: extra, not in spec */ Map<String, Object> didDocumentMetadata) throws RegistrationException {

        throw new UnsupportedOperationException("Not supported yet.");
    }
}
