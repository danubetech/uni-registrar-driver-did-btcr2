package uniregistrar.driver.did.btcr2.states.update;

import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.connections.bitcoin.*;
import uniregistrar.driver.did.btcr2.job.Job;
import uniregistrar.driver.did.btcr2.job.JobRegistry;
import uniregistrar.driver.did.btcr2.util.VerificationMethodTemplateUtil;
import uniregistrar.openapi.model.*;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class TransitionInit {

    public static UpdateState transitionToInitGetVerificationMethod(BitcoinConnection bitcoinConnection) throws RegistrationException {

        // REGISTRATION STATE: jobId

        // REGISTRATION STATE: didState.state="action"

        VerificationMethodTemplate initialVerificationMethodTemplate = VerificationMethodTemplateUtil.createInitialVerificationMethodTemplate();

        // REGISTRATION STATE: didState.did

        // REGISTRATION STATE: didState.secret

        // REGISTRATION STATE: didState.didDocument

        // REGISTRATION STATE: didDocumentMetadata

        Map<String, Object> didDocumentMetadata = new LinkedHashMap<>();
        didDocumentMetadata.put("bitcoinConnection", bitcoinConnection.getClass().getSimpleName());
        switch (bitcoinConnection) {
            case BitcoindRPCBitcoinConnection bitcoindRPCBitcoinConnection:
                didDocumentMetadata.put("rpcURL", bitcoindRPCBitcoinConnection.getBitcoinJsonRpcClient().rpcURL);
                break;
            case BTCDRPCBitcoinConnection btcdrpcBitcoinConnection:
                didDocumentMetadata.put("rpcURL", btcdrpcBitcoinConnection.getBitcoinJsonRpcClient().rpcURL);
                break;
            case EsploraElectrsRESTBitcoinConnection esploraElectrsRESTBitcoinConnection:
                didDocumentMetadata.put("apiEndpointBase", "" + esploraElectrsRESTBitcoinConnection.getApiEndpointBase());
                break;
            case BitcoinjSPVBitcoinConnection bitcoinjSPVBitcoinConnection:
                didDocumentMetadata.put("chain", "" + bitcoinjSPVBitcoinConnection.getWalletAppKit().chain());
                didDocumentMetadata.put("network", "" + bitcoinjSPVBitcoinConnection.getWalletAppKit().network());
                break;
            case BlockcypherAPIBitcoinConnection blockcypherAPIBitcoinConnection:
                break;
            default:
                throw new IllegalStateException("Unexpected bitcoin connection type: " + bitcoinConnection.getClass().getSimpleName());
        }

        // done

        DidStateAction didStateAction = new DidStateAction();
        didStateAction.setState("action");
        didStateAction.setAction("getVerificationMethod");
        didStateAction.setVerificationMethodTemplate(Collections.singletonList(initialVerificationMethodTemplate));

        UpdateState updateState = new UpdateState();
        updateState.setDidState(didStateAction);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        return updateState;
    }

    public static UpdateState transitionToFinished(JobRegistry jobRegistry, Job job, BitcoinConnection bitcoinConnection, String btcr2Did, Map<String, Object> didDocumentMetadata) {

        // REGISTRATION STATE: jobId

        if (job != null) jobRegistry.removeJob(job);

        // REGISTRATION STATE: didState.state="finished"

        // REGISTRATION STATE: didState.did

        String did = btcr2Did;

        // REGISTRATION STATE: didState.secret

        DidStateSecret didStateSecret = new DidStateSecret();

        VerificationMethodTemplate initialVerificationMethodTemplate = VerificationMethodTemplateUtil.createInitialVerificationMethodTemplate();
        VerificationMethodTemplate finishedVerificationMethodTemplate = VerificationMethodTemplateUtil.createFinishedVerificationMethodTemplate(did);

        List<VerificationMethodTemplate> verificationMethodList = List.of(initialVerificationMethodTemplate, finishedVerificationMethodTemplate);

        SecretVerificationMethodInner secretVerificationMethodInner = new SecretVerificationMethodInner();
        secretVerificationMethodInner.setActualInstance(verificationMethodList);

        didStateSecret.setVerificationMethod(Collections.singletonList(secretVerificationMethodInner));

        // REGISTRATION STATE: didState.didDocument

        // REGISTRATION STATE: didDocumentMetadata

        didDocumentMetadata.put("bitcoinConnection", bitcoinConnection.getClass().getSimpleName());
        switch (bitcoinConnection) {
            case BitcoindRPCBitcoinConnection bitcoindRPCBitcoinConnection:
                didDocumentMetadata.put("rpcURL", bitcoindRPCBitcoinConnection.getBitcoinJsonRpcClient().rpcURL);
                break;
            case BTCDRPCBitcoinConnection btcdrpcBitcoinConnection:
                didDocumentMetadata.put("rpcURL", btcdrpcBitcoinConnection.getBitcoinJsonRpcClient().rpcURL);
                break;
            case EsploraElectrsRESTBitcoinConnection esploraElectrsRESTBitcoinConnection:
                didDocumentMetadata.put("apiEndpointBase", "" + esploraElectrsRESTBitcoinConnection.getApiEndpointBase());
                break;
            case BitcoinjSPVBitcoinConnection bitcoinjSPVBitcoinConnection:
                didDocumentMetadata.put("chain", "" + bitcoinjSPVBitcoinConnection.getWalletAppKit().chain());
                didDocumentMetadata.put("network", "" + bitcoinjSPVBitcoinConnection.getWalletAppKit().network());
                break;
            case BlockcypherAPIBitcoinConnection blockcypherAPIBitcoinConnection:
                break;
            default:
                throw new IllegalStateException("Unexpected bitcoin connection type: " + bitcoinConnection.getClass().getSimpleName());
        }

        // done

        DidStateFinished didStateFinished = new DidStateFinished();
        didStateFinished.setState("finished");
        didStateFinished.setDid(did);
        didStateFinished.setSecret(didStateSecret);

        UpdateState updateState = new UpdateState();
        updateState.setDidState(didStateFinished);
        updateState.setDidDocumentMetadata(didDocumentMetadata);

        return updateState;
    }
}
