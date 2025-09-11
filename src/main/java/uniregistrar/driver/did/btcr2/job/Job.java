package uniregistrar.driver.did.btcr2.job;

import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnection;

import java.util.UUID;

public class Job {

    private String jobId;
    private BitcoinConnection bitcoinConnection;
    private Integer nextState;
    private String btcr2Did;
    private String nymRequest;
    private String attribRequest;

    public Job(String jobId, BitcoinConnection bitcoinConnection) {
        this.jobId = jobId;
        this.bitcoinConnection = bitcoinConnection;
    }

    public Job(BitcoinConnection bitcoinConnection) {
        this(UUID.randomUUID().toString(), bitcoinConnection);
    }

    public String getJobId() {
        return jobId;
    }

    public void setJobId(String jobId) {
        this.jobId = jobId;
    }

    public BitcoinConnection getBitcoinConnection() {
        return bitcoinConnection;
    }

    public void setBitcoinConnection(BitcoinConnection bitcoinConnection) {
        this.bitcoinConnection = bitcoinConnection;
    }

    public Integer getNextState() {
        return nextState;
    }

    public void setNextState(Integer nextState) {
        this.nextState = nextState;
    }

    public String getBtcr2Did() {
        return btcr2Did;
    }

    public void setBtcr2Did(String btcr2Did) {
        this.btcr2Did = btcr2Did;
    }
}
