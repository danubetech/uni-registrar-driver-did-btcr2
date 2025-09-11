package uniregistrar.driver.did.btcr2.connections.bitcoin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.driver.did.btcr2.Network;
import wf.bitcoin.javabitcoindrpcclient.BitcoinJSONRPCClient;

import java.util.Map;

public class BitcoinConnector {

	private static final Logger log = LoggerFactory.getLogger(BitcoinConnector.class);

	private Map<Network, BitcoinConnection> bitcoinConnections;
	private Map<Network, String> genesisHashes;

	private BitcoinConnector(Map<Network, BitcoinConnection> bitcoinConnections, Map<Network, String> genesisHashes) {
		if (log.isDebugEnabled()) log.debug("Creating BitcoinConnections: " + bitcoinConnections + " - " + genesisHashes);
		this.bitcoinConnections = bitcoinConnections;
		this.genesisHashes = genesisHashes;
	}

	public static BitcoinConnector create(Map<Network, BitcoinConnection> bitcoinConnections, Map<Network, String> genesisHash) {
		return new BitcoinConnector(bitcoinConnections, genesisHash);
	}

	public static BitcoinConnector create() {
		return create(
				Map.of(
						Network.bitcoin, BitcoindRPCBitcoinConnection.create(BitcoinJSONRPCClient.DEFAULT_JSONRPC_URL),
						Network.regtest, BitcoindRPCBitcoinConnection.create(BitcoinJSONRPCClient.DEFAULT_JSONRPC_REGTEST_URL),
						Network.testnet3, BitcoindRPCBitcoinConnection.create(BitcoinJSONRPCClient.DEFAULT_JSONRPC_TESTNET_URL),
						Network.testnet4, BitcoindRPCBitcoinConnection.create(BitcoinJSONRPCClient.DEFAULT_JSONRPC_TESTNET_URL)),
				Map.of(
						Network.bitcoin, "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
						Network.signet, "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000",
						Network.regtest, "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
						Network.testnet3, "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
						Network.testnet4, "43f08bdab050e35b567c864b91f47f50ae725ae2de53bcfbbaf284da00000000")
				);
	}

	public BitcoinConnection getBitcoinConnection(Network network) {
		BitcoinConnection bitcoinConnection = this.bitcoinConnections.get(network);
		if (bitcoinConnection == null) throw new IllegalArgumentException("Unknown network for bitcoinConnection: " + network);
		if (log.isDebugEnabled()) log.debug("bitcoinConnection for " + network + ": " + bitcoinConnection.getClass().getName());
		return bitcoinConnection;
	}

	public String getGensisHash(Network network) {
		String genesisHash = this.genesisHashes.get(network);
		if (genesisHash == null) throw new IllegalArgumentException("Unknown network for genesisHash: " + network);
		if (log.isDebugEnabled()) log.debug("genesisHash for " + network + ": " + genesisHash);
		return genesisHash;
	}
}
