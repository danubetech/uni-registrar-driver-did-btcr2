package uniregistrar.driver.did.btcr2.connections.bitcoin;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.bitcoinj.kits.WalletAppKit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.driver.did.btcr2.Network;

import java.io.File;

public class BitcoinjSPVBitcoinConnection extends AbstractBitcoinConnection implements BitcoinConnection {

	private static final Logger log = LoggerFactory.getLogger(BitcoindRPCBitcoinConnection.class);

	private static final ObjectMapper mapper;

	private final WalletAppKit walletAppKit;

	static {
		mapper = new ObjectMapper();
		mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
	}

	private BitcoinjSPVBitcoinConnection(WalletAppKit walletAppKit) {
		if (log.isDebugEnabled()) log.debug("Creating BitcoindRPCBitcoinConnection: " + walletAppKit);
		this.walletAppKit = walletAppKit;
	}

	public static BitcoinjSPVBitcoinConnection create(Network network) {
		if (log.isDebugEnabled()) log.debug("Creating BitcoindRPCBitcoinConnection: " + network);
		return new BitcoinjSPVBitcoinConnection(WalletAppKit.launch(network.toBitcoinjNetwork(), new File("."), network.name()));
	}

	/*
	 * Getters and setters
	 */

	public WalletAppKit getWalletAppKit() {
		return walletAppKit;
	}
}