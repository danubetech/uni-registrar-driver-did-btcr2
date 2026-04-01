package uniregistrar.driver.did.btcr2.crud.update;

import java.util.List;

public record UpdateProcessUpdateSignPayloadResult(byte[] btcr2UpdateAnnouncement, List<byte[]> utxoSignPayloads) {
}
