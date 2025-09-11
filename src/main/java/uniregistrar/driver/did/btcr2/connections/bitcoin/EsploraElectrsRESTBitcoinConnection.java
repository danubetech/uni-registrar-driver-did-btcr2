package uniregistrar.driver.did.btcr2.connections.bitcoin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.bitcoinj.base.Address;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.driver.did.btcr2.connections.bitcoin.records.Block;
import uniregistrar.driver.did.btcr2.connections.bitcoin.records.Tx;
import uniregistrar.driver.did.btcr2.connections.bitcoin.records.TxIn;
import uniregistrar.driver.did.btcr2.connections.bitcoin.records.TxOut;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.List;
import java.util.Map;

public class EsploraElectrsRESTBitcoinConnection extends AbstractBitcoinConnection implements BitcoinConnection {

	private static final Logger log = LoggerFactory.getLogger(EsploraElectrsRESTBitcoinConnection.class);

	private static final ObjectMapper objectMapper;

	private final URI apiEndpointBase;

	static {
		objectMapper = new ObjectMapper();
		objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
	}

	private EsploraElectrsRESTBitcoinConnection(URI apiEndpointBase) {
		if (log.isDebugEnabled()) log.debug("Creating EsploraElectrsRESTBitcoinConnection: " + apiEndpointBase);
		this.apiEndpointBase = apiEndpointBase;
	}

	public static EsploraElectrsRESTBitcoinConnection create(URI apiEndpointBase) {
		if (log.isDebugEnabled()) log.debug("Creating EsploraElectrsRESTBitcoinConnection: " + apiEndpointBase);
		return new EsploraElectrsRESTBitcoinConnection(apiEndpointBase);
	}

	@Override
	public Block getBlockByBlockHeight(Integer blockHeight) {
		URI apiEndpoint1 = URI.create(this.apiEndpointBase + "block-height/" + blockHeight);
		Map<String, Object> response1 = readObject(apiEndpoint1);
		URI apiEndpoint2 = URI.create(this.apiEndpointBase + "block/" + response1.get("height") + "/txs");
		List<Object> response2 = readArray(apiEndpoint2);
		Integer responseBlockHeight = ((Number) response1.get("height")).intValue();
		String responseHash = (String) response1.get("id");
		throw new RuntimeException("Not implemented");
	}

	@Override
	public List<Tx> getAddressTransactions(Address address) {
		URI apiEndpoint = URI.create(this.apiEndpointBase + "address/" + address + "/txs");
		List<Object> response = readArray(apiEndpoint);
		List<Tx> txs = response.stream().map(Map.class::cast).map(EsploraElectrsRESTBitcoinConnection::txFromMap).toList();
		if (log.isDebugEnabled()) log.debug("getAddressTransactions for {}: {}", address, txs);
		return txs;
	}

	@Override
	public Block getBlockByTransaction(String txid) {
		URI apiEndpoint = URI.create(this.apiEndpointBase + "tx/" + txid);
		Map<String, Object> response = readObject(apiEndpoint);
		Map<String, Object> status = (Map<String, Object>) response.get("status");
		Integer blockHeight = status == null ? null : ((Number) status.get("block_height")).intValue();
		String blockHash = status == null ? null : (String) status.get("block_hash");
		Long blockTime = status == null ? null : ((Number) status.get("block_time")).longValue();
		List<Tx> txs = null;
		Block block = new Block(blockHeight, blockHash, blockTime, txs);
		if (log.isDebugEnabled()) log.debug("getBlockByTransaction for {}: {}", txid, block);
		return block;
	}

	/*
	 * Helper methods
	 */

	private static Tx txFromMap(Map<String, Object> map) {
		String txId = (String) map.get("txid");
		String txHex = null;
		List<TxIn> txIns = ((List<Map<String, Object>>) map.get("vin")).stream().map(EsploraElectrsRESTBitcoinConnection::txInFromMap).toList();
		List<TxOut> txOuts = ((List<Map<String, Object>>) map.get("vout")).stream().map(EsploraElectrsRESTBitcoinConnection::txOutFromMap).toList();
		return new Tx(txId, txHex, txIns, txOuts);
	}

	private static TxIn txInFromMap(Map<String, Object> map) {
		String txId = (String) map.get("txid");
		Integer vout = ((Number) map.get("vout")).intValue();
		return new TxIn(txId, vout);
	}

	private static TxOut txOutFromMap(Map<String, Object> map) {
		String txId = (String) map.get("txid");
		String scriptPubKeyAddress = (String) map.get("scriptpubkey_address");
		String asm = (String) map.get("scriptpubkey_asm");
		return new TxOut(txId, scriptPubKeyAddress, asm);
	}

	private static String readString(URI uri) {
		HttpURLConnection connection;
		StringBuilder buffer = new StringBuilder();
		try {
			connection = (HttpURLConnection) uri.toURL().openConnection();
			int httpStatus = connection.getResponseCode();
			if (httpStatus != HttpURLConnection.HTTP_OK) throw new IOException("Unexpected HTTP status: " + httpStatus);
			try (InputStream inputStream = connection.getInputStream()) {
				if (inputStream == null) throw new IOException("No input stream");
				if (connection.getInputStream() != null) {
					BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
					String inputLine;
					while ((inputLine = in.readLine()) != null) buffer.append(inputLine);
					in.close();
				}
			}
		} catch (IOException ex) {
			throw new RuntimeException("Cannot read from " + uri + "; " + ex.getMessage(), ex);
		}
		if (log.isDebugEnabled()) log.debug("Read response from " + uri + ": " + buffer);
		return buffer.toString();
    }

	private static Map<String, Object> readObject(URI uri) {
		try {
			return (Map<String, Object>) objectMapper.readValue(readString(uri), Map.class);
		} catch (JsonProcessingException ex) {
			throw new RuntimeException("Cannot parse object response from " + uri + "; " + ex.getMessage(), ex);
		}
	}

	private static List<Object> readArray(URI uri) {
		try {
			return (List<Object>) objectMapper.readValue(readString(uri), List.class);
		} catch (JsonProcessingException ex) {
			throw new RuntimeException("Cannot parse array response from " + uri + "; " + ex.getMessage(), ex);
		}
	}

	/*
	 * Getters and setters
	 */

	public URI getApiEndpointBase() {
		return apiEndpointBase;
	}
}
