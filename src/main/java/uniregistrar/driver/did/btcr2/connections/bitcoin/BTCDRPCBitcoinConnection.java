package uniregistrar.driver.did.btcr2.connections.bitcoin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wf.bitcoin.javabitcoindrpcclient.BitcoinJSONRPCClient;

import java.net.URL;
import java.util.Map;

public class BTCDRPCBitcoinConnection extends AbstractBitcoinConnection implements BitcoinConnection {

	private static final Logger log = LoggerFactory.getLogger(BTCDRPCBitcoinConnection.class);

	private final BitcoinJSONRPCClient bitcoindRpcClient;

	private BTCDRPCBitcoinConnection(BitcoinJSONRPCClient bitcoindRpcClient) {
		if (log.isDebugEnabled()) log.debug("Creating BTCDRPCBitcoinConnection: " + bitcoindRpcClient);
		this.bitcoindRpcClient = bitcoindRpcClient;
	}

	public static BTCDRPCBitcoinConnection create(URL rpcUrl) {
		if (log.isDebugEnabled()) log.debug("Creating BTCDRPCBitcoinConnection: " + rpcUrl);
		return new BTCDRPCBitcoinConnection(new BitcoinJSONRPCClient(rpcUrl));
	}

	@Override
	public Map<String, Object> getMetadata() {
		return Map.of(
				"apiEndpointBase", "" + this.getBitcoinJsonRpcClient().rpcURL);
	}

	/*
	 * Getters and setters
	 */

	public BitcoinJSONRPCClient getBitcoinJsonRpcClient() {
		return bitcoindRpcClient;
	}
}
