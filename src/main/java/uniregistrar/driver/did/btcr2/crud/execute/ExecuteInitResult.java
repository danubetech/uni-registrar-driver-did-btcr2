package uniregistrar.driver.did.btcr2.crud.execute;

import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;

public record ExecuteInitResult(byte[] initialKey, DIDDocument genesisDocument, DID did) {
}
