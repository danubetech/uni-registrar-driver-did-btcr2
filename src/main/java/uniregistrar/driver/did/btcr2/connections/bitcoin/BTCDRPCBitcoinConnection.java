package uniregistrar.driver.did.btcr2.connections.bitcoin;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wf.bitcoin.javabitcoindrpcclient.BitcoinJSONRPCClient;

import java.net.URL;

public class BTCDRPCBitcoinConnection extends AbstractBitcoinConnection implements BitcoinConnection {

	private static final Logger log = LoggerFactory.getLogger(BTCDRPCBitcoinConnection.class);

	private static final ObjectMapper mapper;

	private final BitcoinJSONRPCClient bitcoindRpcClient;

	static {
		mapper = new ObjectMapper();
		mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
	}

	private BTCDRPCBitcoinConnection(BitcoinJSONRPCClient bitcoindRpcClient) {
		if (log.isDebugEnabled()) log.debug("Creating BTCDRPCBitcoinConnection: " + bitcoindRpcClient);
		this.bitcoindRpcClient = bitcoindRpcClient;
	}

	public static BTCDRPCBitcoinConnection create(URL rpcUrl) {
		if (log.isDebugEnabled()) log.debug("Creating BTCDRPCBitcoinConnection: " + rpcUrl);
		return new BTCDRPCBitcoinConnection(new BitcoinJSONRPCClient(rpcUrl));
	}

	/*
	 * Getters and setters
	 */

	public BitcoinJSONRPCClient getBitcoinJsonRpcClient() {
		return bitcoindRpcClient;
	}
}
