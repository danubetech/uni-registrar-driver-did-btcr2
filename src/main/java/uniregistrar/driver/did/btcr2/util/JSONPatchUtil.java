package uniregistrar.driver.did.btcr2.util;

import foundation.identity.did.DIDDocumentV1_1;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonPatch;

import java.io.StringWriter;

public class JSONPatchUtil {

    public static DIDDocumentV1_1 apply(DIDDocumentV1_1 didDocument, JsonPatch jsonPatch) {
        JsonObject didDocumentObject = Json.createObjectBuilder(didDocument.toMap()).build();
        JsonObject patchedDidDocumentObject = jsonPatch.apply(didDocumentObject);
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).write(patchedDidDocumentObject);
        return DIDDocumentV1_1.fromJson(stringWriter.toString());
    }
}
