package uniregistrar.driver.did.btcr2.connections.ipfs;

import io.ipfs.api.IPFS;
import io.ipfs.multiaddr.MultiAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IPFSConnection {

	private static final Logger log = LoggerFactory.getLogger(IPFSConnection.class);

	private final MultiAddress ipfsMultiaddr;

	private IPFS ipfs;

	private IPFSConnection(MultiAddress ipfsMultiaddr) {
		if (log.isDebugEnabled()) log.debug("Creating IPFSConnection: " + ipfsMultiaddr);
		this.ipfsMultiaddr = ipfsMultiaddr;
	}

	public static IPFSConnection create(String ipfsMultiaddr) {
		if (log.isDebugEnabled()) log.debug("Creating IPFSConnection: " + ipfsMultiaddr);
		return new IPFSConnection(new MultiAddress(ipfsMultiaddr));
	}

	public IPFS getIpfs() {
		if (this.ipfs == null) this.ipfs = new IPFS(this.getIpfsMultiaddr());
		if (log.isDebugEnabled()) log.debug("getIpfs: " + this.ipfs);
		return this.ipfs;
	}

	/*
	 * Getters and setters
	 */

	public MultiAddress getIpfsMultiaddr() {
		return this.ipfsMultiaddr;
	}
}
