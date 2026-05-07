package uniregistrar.driver.did.btcr2.crud.execute;

import com.danubetech.btc.connection.BitcoinConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;

import java.util.Map;

public class Execute {

    private static final Logger log = LoggerFactory.getLogger(Execute.class);

    private IPFSConnection ipfsConnection;

    public Execute(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }

    public ExecuteInitResult execute(BitcoinConnection bitcoinConnection, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        // done

        // result

        ExecuteInitResult executeInitResult = new ExecuteInitResult(null);
        if (log.isDebugEnabled()) log.debug("Execute: " + executeInitResult);
        return executeInitResult;
    }

    /*
     * Getters and setters
     */

    public IPFSConnection getIpfsConnection() {
        return ipfsConnection;
    }

    public void setIpfsConnection(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }
}
