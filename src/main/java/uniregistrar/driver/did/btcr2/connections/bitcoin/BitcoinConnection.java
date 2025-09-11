package uniregistrar.driver.did.btcr2.connections.bitcoin;

import org.bitcoinj.base.Address;
import uniregistrar.driver.did.btcr2.connections.bitcoin.records.Block;
import uniregistrar.driver.did.btcr2.connections.bitcoin.records.Tx;

import java.util.List;

public interface BitcoinConnection {

    Block getBlockByBlockHeight(Integer blockHeight);
    Tx getTransactionById(String txid);
    Block getBlockByTargetTime(Long targetTime);
    Block getBlockByMinConfirmations(Integer confirmations);
    List<Tx> getAddressTransactions(Address address);
    Block getBlockByTransaction(String txid);
}
