package uniregistrar.driver.did.btcr2;

import com.danubetech.btc.connection.BitcoinConnector;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.Driver;
import uniregistrar.driver.did.btcr2.config.Configuration;
import uniregistrar.driver.did.btcr2.crud.create.Create;
import uniregistrar.driver.did.btcr2.crud.deactivate.Deactivate;
import uniregistrar.driver.did.btcr2.crud.update.Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.job.CreateJob;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.openapi.model.*;

import java.util.Map;

public class DidBtcr2Driver implements Driver {

	private static final Logger log = LoggerFactory.getLogger(DidBtcr2Driver.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder().build();

	private Map<String, Object> properties;

    private Create create;
    private Update update;
    private Deactivate deactivate;
    private BitcoinConnector bitcoinConnector;
    private IPFSConnection ipfsConnection;

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

        // execute operation

        if (createJob == null) {
            return uniregistrar.driver.did.btcr2.states.create.StateInit.create(createJob, createRequest, this.getCreate(), this.getBitcoinConnector(), this.getIpfsConnection());
        } else {
            throw new RegistrationException("Invalid state for job " + createJob);
        }
    }

    @Override
    public UpdateState update(UpdateRequest updateRequest) throws RegistrationException {

        // read input fields

        Map<String, Object> jobId = updateRequest.getJobId() == null ? null : (updateRequest.getJobId().getMap() == null ? null : updateRequest.getJobId().getMap());
        Boolean clientSecretMode = updateRequest.getOptions() == null ? null : updateRequest.getOptions().getClientSecretMode();

        // check client-managed secret mode

        if (! Boolean.TRUE.equals(clientSecretMode)) {
            throw new RegistrationException("This driver only supports clientSecretMode=true");
        }

        // restore job

        UpdateJob updateJob = jobId == null ? null : UpdateJob.fromJsonObject(jobId);

        // execute operation

        if (updateJob == null || (updateJob.updateSignPayload() == null && updateJob.utxoSignPayloads() == null)) {
            return uniregistrar.driver.did.btcr2.states.update.StateInit.update(updateJob, updateRequest, this.getUpdate(), this.getBitcoinConnector(), this.getIpfsConnection());
        } else if (updateJob.updateSignPayload() != null && updateJob.utxoSignPayloads() == null) {
            return uniregistrar.driver.did.btcr2.states.update.StateProcessUpdateSignPayload.update(updateJob, updateRequest, this.getUpdate(), this.getBitcoinConnector(), this.getIpfsConnection());
        } else if (updateJob.updateSignPayload() == null && updateJob.utxoSignPayloads() != null) {
            return uniregistrar.driver.did.btcr2.states.update.StateProcessUtxoSignPayloads.update(updateJob, updateRequest, this.getUpdate(), this.getBitcoinConnector(), this.getIpfsConnection());
        } else {
            throw new RegistrationException("Invalid state for job " + updateJob);
        }
    }

    private static final String PATCH_DEACTIVATE = """
      {
        "op": "add",
        "path": "/",
        "value": {
          "deactivated": true
        }
      }
    """;

    @Override
    public DeactivateState deactivate(DeactivateRequest deactivateRequest) throws RegistrationException {

        // treat deactivate() request like a special type of update() request

        UpdateRequest updateRequest;

        try {
            updateRequest = jsonMapper.readValue(jsonMapper.writeValueAsString(deactivateRequest), UpdateRequest.class);
            updateRequest.addDidDocumentOperationItem("patchDidDocument");
            updateRequest.addDidDocumentItem(jsonMapper.readValue(PATCH_DEACTIVATE, DidDocument.class));
        } catch (JsonProcessingException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot convert deactivate() request to update() request.");
        }

        // call update()

        UpdateState updateState = this.update(updateRequest);

        // treat update() state like a special type of deactivate() state

        DeactivateState deactivateState;

        try {
            deactivateState = jsonMapper.readValue(jsonMapper.writeValueAsString(updateState), DeactivateState.class);
        } catch (JsonProcessingException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Cannot convert update() state to deactivate() state.");
        }

        // done

        return deactivateState;
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

    public IPFSConnection getIpfsConnection() {
        return ipfsConnection;
    }

    public void setIpfsConnection(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }
}
