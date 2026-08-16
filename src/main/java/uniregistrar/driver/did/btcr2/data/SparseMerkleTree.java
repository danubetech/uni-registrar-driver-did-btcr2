package uniregistrar.driver.did.btcr2.data;

import uniregistrar.driver.did.btcr2.util.SHA256Util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SparseMerkleTree {

    public static final int TREE_DEPTH = 256;

    private static final byte[] EMPTY_HASH = new byte[32];
    private static final byte[][] ZERO_CACHE = new byte[TREE_DEPTH+1][];

    static {
        byte[] hash = EMPTY_HASH;
        for  (int i=0; i<=TREE_DEPTH; i++) {
            hash = SHA256Util.sha256(concat(hash, hash));
            ZERO_CACHE[i] = hash;
        }
    }

    private record Leaf(BigInteger index, byte[] nonce, byte[] updateData) { }

    private final List<Leaf> leaves = new ArrayList<>();

    // -------------------------------------------------------------------------
    // Public API – mutations
    // -------------------------------------------------------------------------

    public void insertUpdate(byte[] didIndex, byte[] nonce, byte[] updateData) {
        leaves.add(new Leaf(new BigInteger(1, didIndex), nonce, updateData));
    }

    public void insertUpdate(byte[] didIndex, byte[] updateHash) {
        this.insertUpdate(didIndex, null, updateHash);
    }

    public void insertUpdate(String did, byte[] nonce, byte[] updateData) {
        this.insertUpdate(didToIndex(did), nonce, updateData);
    }

    public void insertUpdate(String did, byte[] updateHash) {
        this.insertUpdate(didToIndex(did), updateHash);
    }

    public void insertNonUpdate(byte[] didIndex, byte[] nonce) {
        leaves.add(new Leaf(new BigInteger(1, didIndex), nonce, null));
    }

    public void insertNonUpdate(String did, byte[] nonce) {
        this.insertNonUpdate(didToIndex(did), nonce);
    }

    /*
     * Proof Generation
     */

    public byte[] rootHash() {
        return subtreeHash(leaves, TREE_DEPTH);
    }

    public SMTProof generateProof(byte[] didIndex) {
        return this.generateProof(new BigInteger(1, didIndex));
    }

    public SMTProof generateProof(String did) {
        return this.generateProof(didToIndex(did));
    }

    private SMTProof generateProof(BigInteger didIndex) {
        BigInteger collapsed = new BigInteger(1, EMPTY_HASH);
        List<byte[]> siblingHashes = new ArrayList<>();

        for (int level=1; level<=TREE_DEPTH; level++) {
            int bit = TREE_DEPTH - level;
            List<Leaf> siblingLeaves = new ArrayList<>();
            for (Leaf leaf : leaves) {
                if (leaf.index().equals(didIndex)) continue;
                boolean sharesLowerPath = true;
                for (int lower=0; lower<bit; lower++) {
                    if (leaf.index().testBit(lower) != didIndex.testBit(lower)) { sharesLowerPath = false; break; }
                }
                if (sharesLowerPath && leaf.index().testBit(bit) != didIndex.testBit(bit)) siblingLeaves.add(leaf);
            }
            if (siblingLeaves.isEmpty()) {
                collapsed = collapsed.setBit(bit);
            } else {
                siblingHashes.add(subtreeHash(siblingLeaves, level - 1));
            }
        }

        byte[] rootHash = rootHash();
        Leaf leaf = leaves.stream().filter(e -> didIndex.equals(e.index())).findAny().orElse(null);
        if (leaf == null) throw new IllegalArgumentException("DID not found in SMT.");

        return new SMTProof(rootHash, leaf.nonce(), leaf.updateData(), bigIntegerToBytes(collapsed), siblingHashes);
    }

    private static byte[] subtreeHash(List<Leaf> leaves, int level) {

        if (leaves.isEmpty()) return ZERO_CACHE[level];

        if (level == 0) return computeLeafHash(leaves.getFirst());

        int bit = TREE_DEPTH-level;
        List<Leaf> leftLeaves = new ArrayList<>();
        List<Leaf> rightLeaves = new ArrayList<>();

        for (Leaf leaf : leaves) {
            if (leaf.index().testBit(bit)) {
                rightLeaves.add(leaf);
            } else {
                leftLeaves.add(leaf);
            }
        }

        return SHA256Util.sha256(concat(subtreeHash(leftLeaves, level-1), subtreeHash(rightLeaves, level-1)));
    }

    /*
     * Proof Verification
     */

    public static boolean verifyProof(String did, SMTProof smtProof) {

        BigInteger didIndex = new BigInteger(didToIndex(did));
        byte[] candidateHash = computeLeafHash(smtProof.getNonce(), smtProof.getUpdateId());
        BigInteger collapsed = new BigInteger(smtProof.getCollapsed());

        int hashIndex = 0;
        for (int level=0; level<TREE_DEPTH; level++) {

            int bit = TREE_DEPTH-level-1;

            byte[] siblingHash;
            if (collapsed.testBit(bit)) {
                siblingHash = ZERO_CACHE[level];
            } else {
                if (hashIndex >= smtProof.getHashes().size()) return false;
                siblingHash = smtProof.getHashes().get(hashIndex++);
            }

            if (didIndex.testBit(bit)) {
                candidateHash = SHA256Util.sha256(concat(siblingHash, candidateHash));
            } else {
                candidateHash = SHA256Util.sha256(concat(candidateHash, siblingHash));
            }
        }

        return hashIndex == smtProof.getHashes().size() && Arrays.equals(candidateHash, smtProof.getId());
    }

    /*
     * Helper methods
     */

    public static byte[] didToIndex(String did) {
        return SHA256Util.sha256(did.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] computeLeafHash(byte[] nonce, byte[] updateHash) {
        return updateHash != null ? computeLeafForUpdate(nonce, updateHash) : computeLeafForNonUpdate(nonce);
    }

    private static byte[] computeLeafHash(Leaf leaf) {
        return computeLeafHash(leaf.nonce(), leaf.updateData());
    }

    private static byte[] computeLeafForUpdate(byte[] nonce, byte[] updateHash) {
        return nonce == null ? updateHash : SHA256Util.sha256(concat(SHA256Util.sha256(nonce), updateHash));
    }

    private static byte[] computeLeafForNonUpdate(byte[] nonce) {
        return nonce == null ? EMPTY_HASH : SHA256Util.sha256(SHA256Util.sha256(nonce));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static byte[] bigIntegerToBytes(BigInteger bigInteger) {
        if (bigInteger == null) return null;
        byte[] bytes = bigInteger.toByteArray();
        if (bytes.length == 33 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        } else {
            return bytes;
        }
    }
}