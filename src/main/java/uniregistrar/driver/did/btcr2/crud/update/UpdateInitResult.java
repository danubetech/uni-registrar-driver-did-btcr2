package uniregistrar.driver.did.btcr2.crud.update;

import java.net.URI;

public record UpdateInitResult(URI verificationMethodId, byte[] updateSignPayload) {
}
