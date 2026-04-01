package uniregistrar.driver.did.btcr2;

import com.danubetech.btc.connection.BitcoinConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.Driver;
import uniregistrar.driver.did.btcr2.config.Configuration;
import uniregistrar.driver.did.btcr2.crud.create.Create;
import uniregistrar.driver.did.btcr2.crud.deactivate.Deactivate;
import uniregistrar.driver.did.btcr2.crud.update.Update;
import uniregistrar.driver.did.btcr2.job.CreateJob;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.openapi.model.CreateRequest;
import uniregistrar.openapi.model.CreateState;
import uniregistrar.openapi.model.UpdateRequest;
import uniregistrar.openapi.model.UpdateState;

import java.util.Map;

public class DidBtcr2Driver implements Driver {

	private static final Logger log = LoggerFactory.getLogger(DidBtcr2Driver.class);

	private Map<String, Object> properties;

    private Create create;
    private Update update;
    private Deactivate deactivate;
    private BitcoinConnector bitcoinConnector;

	public DidBtcr2Driver() {
		this(Configuration.getPropertiesFromEnvironment());
	}

	public DidBtcr2Driver(Map<String, Object> properties) {
		this.setProperties(properties);
	}

    @Override
    public CreateState create(CreateRequest createRequest) throws RegistrationException {

        // read input fields

        Map<String, Object> jobId = (Map<String, Object>) createRequest.getJobId();
        Boolean clientSecretMode = createRequest.getOptions() == null ? null : createRequest.getOptions().getClientSecretMode();

        // check client-managed secret mode

        if (! Boolean.TRUE.equals(clientSecretMode)) {
            throw new RegistrationException("This driver only supports clientSecretMode=true");
        }

        // restore job

        CreateJob createJob = jobId == null ? null : CreateJob.fromJsonObject(jobId);

        if (createJob == null || createJob.getNextState() == uniregistrar.driver.did.btcr2.states.create.StateInit.STATE) {
            return uniregistrar.driver.did.btcr2.states.create.StateInit.create(createJob, createRequest, this.getCreate(), this.getBitcoinConnector());
        } else {
            throw new RegistrationException("Invalid state " + createJob.getNextState() + " for job " + createJob.getJobId());
        }
    }

    @Override
    public UpdateState update(UpdateRequest updateRequest) throws RegistrationException {

        // read input fields

        Map<String, Object> jobId = (Map<String, Object>) updateRequest.getJobId();
        Boolean clientSecretMode = updateRequest.getOptions() == null ? null : updateRequest.getOptions().getClientSecretMode();

        // check client-managed secret mode

        if (! Boolean.TRUE.equals(clientSecretMode)) {
            throw new RegistrationException("This driver only supports clientSecretMode=true");
        }

        // find job

        UpdateJob updateJob = jobId == null ? null : UpdateJob.fromJsonObject(jobId);

        if (updateJob == null || (updateJob.updateSignPayload() == null && updateJob.utxoSignPayloads() == null)) {
            return uniregistrar.driver.did.btcr2.states.update.StateInit.update(updateJob, updateRequest, this.getUpdate(), this.getBitcoinConnector());
        } else if (updateJob.updateSignPayload() != null && updateJob.utxoSignPayloads() == null) {
            return uniregistrar.driver.did.btcr2.states.update.StateProcessUpdateSignPayload.update(updateJob, updateRequest, this.getUpdate(), this.getBitcoinConnector());
        } else if (updateJob.updateSignPayload() == null && updateJob.utxoSignPayloads() != null) {
            return uniregistrar.driver.did.btcr2.states.update.StateProcessUtxoSignPayloads.update(updateJob, updateRequest, this.getUpdate(), this.getBitcoinConnector());
        } else {
            throw new RegistrationException("Invalid state for job " + updateJob);
        }
    }

	@Override
	public Map<String, Object> properties() {
		return this.getProperties();
	}

	/*
	 * Getters and setters
	 */

	public Map<String, Object> getProperties() {
		return this.properties;
	}

	public void setProperties(Map<String, Object> properties) {
		this.properties = properties;
		Configuration.configureFromProperties(this, properties);
	}

    public Create getCreate() {
        return this.create;
    }

    public void setCreate(Create create) {
        this.create = create;
    }

    public Update getUpdate() {
        return this.update;
    }

    public void setUpdate(Update update) {
        this.update = update;
    }

    public Deactivate getDeactivate() {
        return this.deactivate;
    }

    public void setDeactivate(Deactivate deactivate) {
        this.deactivate = deactivate;
    }

    public BitcoinConnector getBitcoinConnector() {
        return this.bitcoinConnector;
    }

    public void setBitcoinConnector(BitcoinConnector bitcoinConnector) {
        this.bitcoinConnector = bitcoinConnector;
    }
}
