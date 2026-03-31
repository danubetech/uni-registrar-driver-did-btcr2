package uniregistrar.driver.did.btcr2.crud.update;

import java.net.URI;

public class ActionUpdateSignPayloadException extends Exception {

    private final URI verificationMethodId;
    private final byte[] payload;

    public ActionUpdateSignPayloadException(URI verificationMethodId, byte[] payload) {
        this.verificationMethodId = verificationMethodId;
        this.payload = payload;
    }

    public URI getVerificationMethodId() {
        return verificationMethodId;
    }

    public byte[] getPayload() {
        return payload;
    }
}
