package uniregistrar.driver.did.btcr2;

import com.danubetech.btc.connection.BitcoinConnector;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.Driver;
import uniregistrar.driver.did.btcr2.config.Configuration;
import uniregistrar.driver.did.btcr2.crud.create.CreateInit;
import uniregistrar.driver.did.btcr2.crud.deactivate.Deactivate;
import uniregistrar.driver.did.btcr2.crud.execute.Execute;
import uniregistrar.driver.did.btcr2.crud.update.UpdateInit;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUpdateSignPayload;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUtxoAggregateSignPayloads;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUtxoSingletonSignPayloads;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.job.CreateJob;
import uniregistrar.driver.did.btcr2.job.UpdateJob;
import uniregistrar.driver.did.btcr2.states.update.StateProcessUtxoAggregateSignPayloads;
import uniregistrar.driver.did.btcr2.states.update.StateProcessUtxoSingletonSignPayloads;
import uniregistrar.openapi.model.*;

import java.util.Map;

public class DidBtcr2Driver implements Driver {

	private static final Logger log = LoggerFactory.getLogger(DidBtcr2Driver.class);

    private static final JsonMapper jsonMapper = JsonMapper.builder().build();

	private Map<String, Object> properties;

    private CreateInit createInit;
    private UpdateInit updateInit;
    private UpdateProcessUpdateSignPayload updateProcessUpdateSignPayload;
    private UpdateProcessUtxoSingletonSignPayloads updateProcessUtxoSingletonSignPayloads;
    private UpdateProcessUtxoAggregateSignPayloads updateProcessUtxoAggregateSignPayloads;
    private Deactivate deactivate;
    private Execute execute;
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

        CreateJob createJob = jobId == null ? null : CreateJob.fromMap(jobId);

        // execute operation

        if (createJob == null) {
            return uniregistrar.driver.did.btcr2.states.create.StateInit.create(createJob, createRequest, this.getCreateInit(), this.getBitcoinConnector(), this.getIpfsConnection());
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

        UpdateJob updateJob = jobId == null ? null : UpdateJob.fromMap(jobId);

        // execute operation

        if (updateJob == null || (updateJob.updateSignPayload() == null && updateJob.utxoSingletonSignPayloads() == null && updateJob.utxoAggregateSignPayloads() == null)) {
            return uniregistrar.driver.did.btcr2.states.update.StateInit.update(updateJob, updateRequest, this.getUpdateInit(), this.getBitcoinConnector(), this.getIpfsConnection());
        } else if (updateJob.updateSignPayload() != null && updateJob.utxoSingletonSignPayloads() == null && updateJob.utxoAggregateSignPayloads() == null) {
            return uniregistrar.driver.did.btcr2.states.update.StateProcessUpdateSignPayload.update(updateJob, updateRequest, this.getUpdateProcessUpdateSignPayload(), this.getBitcoinConnector(), this.getIpfsConnection());
        } else if (updateJob.utxoSingletonSignPayloads() != null) {
            return StateProcessUtxoSingletonSignPayloads.update(updateJob, updateRequest, this.getUpdateProcessUtxoSingletonSignPayloads(), this.getBitcoinConnector(), this.getIpfsConnection());
        } else if (updateJob.utxoAggregateSignPayloads() != null) {
            return StateProcessUtxoAggregateSignPayloads.update(updateJob, updateRequest, this.getUpdateProcessUtxoAggregateSignPayloads(), this.getBitcoinConnector(), this.getIpfsConnection());
        } else {
            throw new RegistrationException("Invalid state for job " + updateJob);
        }
    }

    private static final String PATCH_DEACTIVATE = """
      {
        "op": "add",
        "path": "/deactivated",
        "value": true
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

    public CreateInit getCreateInit() {
        return createInit;
    }

    public void setCreateInit(CreateInit createInit) {
        this.createInit = createInit;
    }

    public UpdateInit getUpdateInit() {
        return updateInit;
    }

    public void setUpdateInit(UpdateInit updateInit) {
        this.updateInit = updateInit;
    }

    public UpdateProcessUpdateSignPayload getUpdateProcessUpdateSignPayload() {
        return updateProcessUpdateSignPayload;
    }

    public void setUpdateProcessUpdateSignPayload(UpdateProcessUpdateSignPayload updateProcessUpdateSignPayload) {
        this.updateProcessUpdateSignPayload = updateProcessUpdateSignPayload;
    }

    public UpdateProcessUtxoSingletonSignPayloads getUpdateProcessUtxoSingletonSignPayloads() {
        return updateProcessUtxoSingletonSignPayloads;
    }

    public void setUpdateProcessUtxoSingletonSignPayloads(UpdateProcessUtxoSingletonSignPayloads updateProcessUtxoSingletonSignPayloads) {
        this.updateProcessUtxoSingletonSignPayloads = updateProcessUtxoSingletonSignPayloads;
    }

    public UpdateProcessUtxoAggregateSignPayloads getUpdateProcessUtxoAggregateSignPayloads() {
        return updateProcessUtxoAggregateSignPayloads;
    }

    public void setUpdateProcessUtxoAggregateSignPayloads(UpdateProcessUtxoAggregateSignPayloads updateProcessUtxoAggregateSignPayloads) {
        this.updateProcessUtxoAggregateSignPayloads = updateProcessUtxoAggregateSignPayloads;
    }

    public Deactivate getDeactivate() {
        return this.deactivate;
    }

    public void setDeactivate(Deactivate deactivate) {
        this.deactivate = deactivate;
    }

    public Execute getExecute() {
        return this.execute;
    }

    public void setExecute(Execute execute) {
        this.execute = execute;
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
