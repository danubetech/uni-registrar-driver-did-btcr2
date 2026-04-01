package uniregistrar.driver.did.btcr2.crud.update;

import foundation.identity.did.DID;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.job.UpdateJob;

import java.util.List;
import java.util.stream.IntStream;

public record UpdateProcessUtxoSignPayloadsResult(DID did) {

}
