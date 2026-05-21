package uniregistrar.driver.did.btcr2.data;

import uniregistrar.driver.did.btcr2.util.SHA256Util;

import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) throws Exception {
        SparseMerkleTree sparseMerkleTree = new SparseMerkleTree();
        sparseMerkleTree.insertUpdate("did:ex:1234", SHA256Util.sha256("a0".getBytes(StandardCharsets.UTF_8)));
        SMTProof smtProof = sparseMerkleTree.generateProof("did:ex:1234");
        System.out.println(smtProof.toBtcr2Map());
        System.out.println(smtProof.toString());
    }
}
