package uniregistrar.driver.did.btcr2.crud.update;

import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;

import java.net.URI;

public record UpdateInitResult(URI verificationMethodId, BTCR2Update btcr2Update, byte[] updateSignPayload) {
}
