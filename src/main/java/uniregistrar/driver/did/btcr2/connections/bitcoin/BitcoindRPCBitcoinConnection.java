package uniregistrar.driver.did.btcr2.connections.bitcoin;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.driver.did.btcr2.connections.bitcoin.records.Block;
import uniregistrar.driver.did.btcr2.connections.bitcoin.records.Tx;
import uniregistrar.driver.did.btcr2.connections.bitcoin.records.TxIn;
import uniregistrar.driver.did.btcr2.connections.bitcoin.records.TxOut;
import wf.bitcoin.javabitcoindrpcclient.BitcoinJSONRPCClient;

import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;

public class BitcoindRPCBitcoinConnection extends AbstractBitcoinConnection implements BitcoinConnection {

	private static final Logger log = LoggerFactory.getLogger(BitcoindRPCBitcoinConnection.class);

	private static final ObjectMapper mapper;

	private final BitcoinJSONRPCClient bitcoindRpcClient;

	static {
		mapper = new ObjectMapper();
		mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
	}

	private BitcoindRPCBitcoinConnection(BitcoinJSONRPCClient bitcoindRpcClient) {
		if (log.isDebugEnabled()) log.debug("Creating BitcoindRPCBitcoinConnection: " + bitcoindRpcClient);
		this.bitcoindRpcClient = bitcoindRpcClient;
	}

	public static BitcoindRPCBitcoinConnection create(URL rpcUrl) {
		if (log.isDebugEnabled()) log.debug("Creating BitcoindRPCBitcoinConnection: " + rpcUrl);
		return new BitcoindRPCBitcoinConnection(new BitcoinJSONRPCClient(rpcUrl));
	}

	@Override
	public Block getBlockByBlockHeight(Integer blockHeight) {
		BitcoinJSONRPCClient bitcoinJSONRPCClient = this.getBitcoinJsonRpcClient();
		wf.bitcoin.javabitcoindrpcclient.BitcoindRpcClient.Block bitcoinjBlock = bitcoinJSONRPCClient.getBlock(blockHeight);
		List<Tx> txs = bitcoinjBlock.tx().stream().map(tx -> txFromBitcoinjRawTransaction(bitcoinJSONRPCClient, tx)).collect(Collectors.toList());
		Block block = new Block(bitcoinjBlock.height(), bitcoinjBlock.hash(), bitcoinjBlock.time().getTime(), txs);
		if (log.isDebugEnabled()) log.debug("getBlockByBlockHeight for {}: {}", blockHeight, block);
		return block;
	}

	@Override
	public Tx getTransactionById(String txId) {
		BitcoinJSONRPCClient bitcoinJSONRPCClient = this.getBitcoinJsonRpcClient();
		Tx tx = txFromBitcoinjRawTransaction(bitcoinJSONRPCClient, txId);
		if (log.isDebugEnabled()) log.debug("getTransactionById for {}: {}", txId, tx);
		return tx;
	}

	@Override
	public Block getBlockByTargetTime(Long targetTime) {
		BitcoinJSONRPCClient bitcoinJSONRPCClient = this.getBitcoinJsonRpcClient();
		Integer blocks = bitcoinJSONRPCClient.getBlockChainInfo().blocks();
		Block block = null;
		for (int blockHeight=blocks-1; blockHeight>=0; blockHeight--) {
			wf.bitcoin.javabitcoindrpcclient.BitcoindRpcClient.Block bitcoinjBlock = bitcoinJSONRPCClient.getBlock(blockHeight);
			if (bitcoinjBlock.time().getTime() < targetTime) {
				block = new Block(bitcoinjBlock.height(), bitcoinjBlock.hash(), bitcoinjBlock.time().getTime(), null);
				break;
			}
		}
		if (log.isDebugEnabled()) log.debug("getBlockByTargetTime for {}: {}", targetTime, block);
		return block;
	}

	@Override
	public Block getBlockByMinConfirmations(Integer minConfirmations) {
		BitcoinJSONRPCClient bitcoinJSONRPCClient = this.getBitcoinJsonRpcClient();
		Integer blocks = bitcoinJSONRPCClient.getBlockChainInfo().blocks();
		Block block = null;
		for (int blockHeight=blocks-1; blockHeight>=0; blockHeight--) {
			wf.bitcoin.javabitcoindrpcclient.BitcoindRpcClient.Block bitcoinjBlock = bitcoinJSONRPCClient.getBlock(blockHeight);
			if (bitcoinjBlock.confirmations() >= minConfirmations) {
				block = new Block(bitcoinjBlock.height(), bitcoinjBlock.hash(), bitcoinjBlock.time().getTime(), null);
				break;
			}
		}
		if (log.isDebugEnabled()) log.debug("getBlockByMinConfirmations for {}: {}", minConfirmations, block);
		return block;
	}

	/*
	 * Helper methods
	 */

	private static Tx txFromBitcoinjRawTransaction(BitcoinJSONRPCClient bitcoinJSONRPCClient, String txId) {
		if (Tx.COINBASE_TX_IDENTIFIER.equals(txId) || Tx.GENESIS_TX_IDENTIFIER.equals(txId)) {
			return new Tx(txId, null, null, null);
		}
		wf.bitcoin.javabitcoindrpcclient.BitcoindRpcClient.RawTransaction bitcoinjRawTransaction = bitcoinJSONRPCClient.getRawTransaction(txId);
		String txHex = bitcoinjRawTransaction.hex();
		List<TxIn> txIns = bitcoinjRawTransaction.vIn().stream().map(BitcoindRPCBitcoinConnection::txInFromBitcoinjIn).toList();
		List<TxOut> txOuts = bitcoinjRawTransaction.vOut().stream().map(BitcoindRPCBitcoinConnection::txOutFromBitcoinjOut).toList();
		return new Tx(txId, txHex, txIns, txOuts);
	}

	private static TxIn txInFromBitcoinjIn(wf.bitcoin.javabitcoindrpcclient.BitcoindRpcClient.RawTransaction.In in) {
		String txId = in.txid();
		Integer vout = txId == null ? null : in.getTransactionOutput().n();
		return new TxIn(txId, vout);
	}

	private static TxOut txOutFromBitcoinjOut(wf.bitcoin.javabitcoindrpcclient.BitcoindRpcClient.RawTransaction.Out out) {
		String txId = out.transaction().txId();
		String scriptPubKeyAddress = out.scriptPubKey().mapStr("address");
		String asm = out.scriptPubKey().asm();
		return new TxOut(txId, scriptPubKeyAddress, asm);
	}

	/*
	 * Getters and setters
	 */

	public BitcoinJSONRPCClient getBitcoinJsonRpcClient() {
		return bitcoindRpcClient;
	}
}
