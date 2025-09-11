package uniregistrar.driver.did.btcr2.connections.bitcoin.records;

public record TxOut(
        String txId,
        String scriptPubKeyAddress,
        String asm) {
}
