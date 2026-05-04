package uniregistrar.driver.did.btcr2.crud.execute.create;

import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;

public record CreateInitResult(byte[] initialKey, DIDDocument genesisDocument, DID did) {
}
