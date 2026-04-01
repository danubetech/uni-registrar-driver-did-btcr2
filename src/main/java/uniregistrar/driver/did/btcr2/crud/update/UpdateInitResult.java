package uniregistrar.driver.did.btcr2.crud.update;

import uniregistrar.driver.did.btcr2.job.UpdateJob;

import java.net.URI;

public record UpdateInitResult(URI verificationMethodId, byte[] updateSignPayload) {
}
