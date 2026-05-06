package uniregistrar.driver.did.btcr2.ipfs;

import io.ipfs.api.IPFS;
import io.ipfs.multiaddr.MultiAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class IPFSConnection {

	private static final Logger log = LoggerFactory.getLogger(IPFSConnection.class);

	private final MultiAddress ipfsMultiaddr;
	private final Integer ipfsTimeout;

	private IPFS ipfs;

	private IPFSConnection(MultiAddress ipfsMultiaddr, Integer ipfsTimeout) {
		if (log.isDebugEnabled()) log.debug("Creating IPFSConnection: " + ipfsMultiaddr + ", " + ipfsTimeout);
		this.ipfsMultiaddr = ipfsMultiaddr;
		this.ipfsTimeout = ipfsTimeout;
	}

	public static IPFSConnection create(String ipfsMultiaddr, Integer ipfsTimeout) {
		return new IPFSConnection(new MultiAddress(ipfsMultiaddr), ipfsTimeout);
	}

	public static IPFSConnection create(String ipfsMultiaddr) {
		return new IPFSConnection(new MultiAddress(ipfsMultiaddr), null);
	}

	public IPFS getIpfs() {
		if (this.ipfs == null) {
			this.ipfs = new IPFS(this.getIpfsMultiaddr());
			if (this.getIpfsTimeout() != null) this.ipfs = this.ipfs.timeout(this.getIpfsTimeout());
		}
		if (log.isDebugEnabled()) log.debug("getIpfs: " + this.ipfs.protocol + " " + this.ipfs.host + ":" + this.ipfs.port);
		return this.ipfs;
	}

	public Map<String, Object> getMetadata() {
		return Map.of("ipfsMultiaddr", this.getIpfsMultiaddr().toString());
	}

	/*
	 * Getters and setters
	 */

	public MultiAddress getIpfsMultiaddr() {
		return this.ipfsMultiaddr;
	}

	public Integer getIpfsTimeout() {
		return this.ipfsTimeout;
	}
}
