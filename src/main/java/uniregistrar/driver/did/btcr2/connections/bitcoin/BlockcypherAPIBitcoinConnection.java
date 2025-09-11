package uniregistrar.driver.did.btcr2.connections.bitcoin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BlockcypherAPIBitcoinConnection extends AbstractBitcoinConnection implements BitcoinConnection {

	private static final Logger log = LoggerFactory.getLogger(BlockcypherAPIBitcoinConnection.class);

	private BlockcypherAPIBitcoinConnection() {
		if (log.isDebugEnabled()) log.debug("Creating BlockcypherAPIBitcoinConnection");
	}

	public static BlockcypherAPIBitcoinConnection create() {
		return new BlockcypherAPIBitcoinConnection();
	}
}
