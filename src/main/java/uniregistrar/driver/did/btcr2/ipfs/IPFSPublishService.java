package uniregistrar.driver.did.btcr2.ipfs;

import io.ipfs.api.NamedStreamable;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class IPFSPublishService {

    private static final ExecutorService executorService = Executors.newCachedThreadPool();

    public static void publish(IPFSConnection ipfsConnection, byte[] payload) throws IOException {

        executorService.submit(() -> {
            try {
                ipfsConnection.getIpfs().add(new NamedStreamable.ByteArrayWrapper(payload));
            } catch (IOException ex) {
                throw new RuntimeException(ex.getMessage(), ex);
            }
        });
    }
}
