package uniregistrar.driver.did.btcr2.connections.bitcoin.records;

import java.util.List;

public record Tx(
        String txId,
        String txHex,
        List<TxIn> txIns,
        List<TxOut> txOuts) {

    public static final String COINBASE_TX_IDENTIFIER = "0000000000000000000000000000000000000000000000000000000000000000";
    public static final String GENESIS_TX_IDENTIFIER = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
}
