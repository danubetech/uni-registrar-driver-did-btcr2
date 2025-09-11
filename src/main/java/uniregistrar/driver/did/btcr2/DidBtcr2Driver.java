package uniregistrar.driver.did.btcr2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.Driver;
import uniregistrar.driver.did.btcr2.config.Configuration;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.crud.create.Create;
import uniregistrar.driver.did.btcr2.crud.deactivate.Deactivate;
import uniregistrar.driver.did.btcr2.crud.update.Update;
import uniregistrar.driver.did.btcr2.job.Job;
import uniregistrar.driver.did.btcr2.job.JobRegistry;
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

    private JobRegistry jobRegistry = new JobRegistry();

	public DidBtcr2Driver() {
		this(Configuration.getPropertiesFromEnvironment());
	}

	public DidBtcr2Driver(Map<String, Object> properties) {
		this.setProperties(properties);
	}

    @Override
    public CreateState create(CreateRequest createRequest) throws RegistrationException {

        // read input fields

        String jobId = createRequest.getJobId();
        Boolean clientSecretMode = createRequest.getOptions() == null ? null : createRequest.getOptions().getClientSecretMode();

        // check client-managed secret mode

        if (! Boolean.TRUE.equals(clientSecretMode)) {
            throw new RegistrationException("This driver only supports clientSecretMode=true");
        }

        // find job

        Job job = jobId == null ? null : this.getJobRegistry().getJob(jobId);
        if (jobId != null && job == null) throw new RegistrationException("Job not found: " + jobId);

        if (job == null || job.getNextState() == uniregistrar.driver.did.btcr2.states.create.StateInit.STATE) {
            return uniregistrar.driver.did.btcr2.states.create.StateInit.create(this.getJobRegistry(), job, createRequest, this.getCreate(), this.getBitcoinConnector());
        } else {
            throw new RegistrationException("Invalid state " + job.getNextState() + " for job " + job.getJobId());
        }
    }

    @Override
    public UpdateState update(UpdateRequest updateRequest) throws RegistrationException {

        // read input fields

        String jobId = updateRequest.getJobId();
        Boolean clientSecretMode = updateRequest.getOptions() == null ? null : updateRequest.getOptions().getClientSecretMode();

        // check client-managed secret mode

        if (! Boolean.TRUE.equals(clientSecretMode)) {
            throw new RegistrationException("This driver only supports clientSecretMode=true");
        }

        // find job

        Job job = jobId == null ? null : this.getJobRegistry().getJob(jobId);
        if (jobId != null && job == null) throw new RegistrationException("Job not found: " + jobId);

        if (job == null || job.getNextState() == uniregistrar.driver.did.btcr2.states.create.StateInit.STATE) {
            return uniregistrar.driver.did.btcr2.states.update.StateInit.update(this.getJobRegistry(), job, updateRequest, this.getUpdate(), this.getBitcoinConnector());
        } else {
            throw new RegistrationException("Invalid state " + job.getNextState() + " for job " + job.getJobId());
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

    public JobRegistry getJobRegistry() {
        return this.jobRegistry;
    }

    public void setJobRegistry(JobRegistry jobRegistry) {
        this.jobRegistry = jobRegistry;
    }
}
