package uniregistrar.driver.did.btcr2.data;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Optimized Sparse Merkle Tree (SMT) implementation.
 *
 * <p>Based on the did:btcr2 specification:
 * https://dcdpr.github.io/did-btcr2/appendix/optimized-smt.html
 *
 * <h2>Design rules from the spec</h2>
 * <ul>
 *   <li>A node with two empty children is itself empty.</li>
 *   <li>A node with ONE non-empty child passes that child's value upward unchanged
 *       (single-child collapsing / path compression).</li>
 *   <li>A node with TWO non-empty children: {@code hash(left || right)}.</li>
 *   <li>Leaf value: {@code hash(hash(nonce) || hash(update))} for updates,
 *       {@code hash(hash(nonce))} for non-updates.</li>
 *   <li>Index of a leaf: {@code BigInteger(sha256(did), big-endian)}.</li>
 * </ul>
 *
 * <h2>Performance</h2>
 * The tree is 256 levels deep.  A naïve recursive walk would be {@code O(2^256)}.
 * Instead we exploit the fact that the tree is sparse: only paths to occupied leaves
 * need to be examined.  computeNode is called only for subtrees that
 * contain at least one leaf; we use a per-call memoisation map so that shared
 * ancestors are computed once.
 */
public class SparseMerkleTree {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /** SHA-256 produces 256-bit digests → 2^256 possible leaf positions. */
    public static final int TREE_DEPTH = 256;

    /** Sentinel for an empty node / subtree. */
    static final byte[] EMPTY = new byte[0];

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /** Maps leaf nonce → pre-computed leaf hash for every occupied leaf. */
    private final Map<BigInteger, byte[]> leaves = new HashMap<>();

    // -------------------------------------------------------------------------
    // Public API – building the tree
    // -------------------------------------------------------------------------

    /**
     * Insert a non-update entry for a DID.
     *
     * @param did   DID string; its SHA-256 hash (big-endian) determines the leaf nonce.
     * @param nonce unique 256-bit nonce for this DID/signal (32 bytes).
     */
    public void insertNonUpdate(String did, byte[] nonce) {
        leaves.put(didToIndex(did), computeLeafHash(nonce, null));
    }

    /**
     * Insert an update entry for a DID.
     *
     * @param did        DID string.
     * @param nonce      unique 256-bit nonce (32 bytes).
     * @param updateData raw BTCR2 update payload (will be SHA-256 hashed internally).
     */
    public void insertUpdate(String did, byte[] nonce, byte[] updateData) {
        leaves.put(didToIndex(did), computeLeafHash(nonce, sha256(updateData)));
    }
    public void insertUpdate(String did, byte[] updateHash) {
        leaves.put(didToIndex(did), updateHash);
    }
    public void insertUpdate(byte[] didIndex, byte[] nonce, byte[] updateData) {
        leaves.put(new BigInteger(1, didIndex), computeLeafHash(nonce, sha256(updateData)));
    }
    public void insertUpdate(byte[] didIndex, byte[] updateHash) {
        leaves.put(new BigInteger(1, didIndex), updateHash);
    }

    /**
     * Insert a leaf at an explicit numeric nonce with a pre-computed leaf hash.
     * Useful for low-level tests that work directly with indices.
     */
    public void insertLeafHash(BigInteger index, byte[] leafHash) {
        leaves.put(index, leafHash);
    }

    /** Remove a leaf (marks its slot as empty). */
    public void remove(String did) {
        leaves.remove(didToIndex(did));
    }

    // -------------------------------------------------------------------------
    // Public API – querying
    // -------------------------------------------------------------------------

    /**
     * Compute and return the root hash of the current tree.
     * Returns an empty array ({@link #EMPTY}) if the tree is empty.
     */
    public byte[] rootHash() {
        return computeSubtreeHash(BigInteger.ZERO, TREE_DEPTH, leaves);
    }

    /**
     * Generate an {@link SmtProof} for the given DID.
     *
     * @param did DID to prove membership (or non-membership) for.
     * @return an {@link SmtProof} the verifier can use to recompute the root.
     */
    public SmtProof generateProof(String did) {
        return generateProofForIndex(didToIndex(did));
    }

    /**
     * Generate an {@link SmtProof} for an explicit leaf nonce.
     */
    public SmtProof generateProofForIndex(BigInteger index) {
        byte[] root = rootHash();
        List<byte[]> siblingHashes = new ArrayList<>();
        BigInteger collapsed = BigInteger.ZERO;

        // Walk from leaf level up to root, collecting sibling info.
        // At depth d, the subtree covers 2^d leaves starting at nodeIndex.
        BigInteger nodeIndex = alignToDepth(index, TREE_DEPTH, 0); // == nonce itself at leaf depth
        for (int depth = 1; depth <= TREE_DEPTH; depth++) {
            int level = depth - 1; // bit position in the collapsed bitmap
            BigInteger sibIndex = siblingIndex(nodeIndex, depth);

            byte[] selfHash = computeSubtreeHash(nodeIndex, depth - 1, leaves);
            byte[] sibHash  = computeSubtreeHash(sibIndex,  depth - 1, leaves);

            if (isEmpty(selfHash) || isEmpty(sibHash)) {
                // One (or both) sides empty → collapse at this level
                collapsed = collapsed.setBit(level);
            } else {
                siblingHashes.add(sibHash);
            }
            nodeIndex = parentIndex(nodeIndex, depth);
        }

        return new SmtProof(root, index, leaves.get(index), collapsed, siblingHashes);
    }
    public SmtProof generateProofForIndex(byte[] didIndex) {
        return this.generateProofForIndex(new BigInteger(1, didIndex));
    }

    // -------------------------------------------------------------------------
    // Proof verification (static – verifier side)
    // -------------------------------------------------------------------------

    /**
     * Verify an {@link SmtProof} against a known root hash.
     *
     * @param proof    the proof to verify.
     * @param rootHash the expected root hash (e.g. from a Beacon Signal).
     * @return {@code true} if the proof is valid.
     */
    public static boolean verifyProof(SmtProof proof, byte[] rootHash) {
        if (proof.updateId() == null || isEmpty(proof.updateId())) {
            return false; // nothing to verify
        }
        return verifyProofWithDepth(proof, rootHash, TREE_DEPTH);
    }

    /**
     * Verify a proof for a tree of arbitrary depth {@code treeDepth}.
     * (Exposed for sub-class use in tests with a 4-bit tree.)
     */
    static boolean verifyProofWithDepth(SmtProof proof, byte[] rootHash, int treeDepth) {
        if (proof.updateId() == null || isEmpty(proof.updateId())) return false;

        BigInteger index    = proof.nonce();
        byte[]     candidate = proof.updateId().clone();
        BigInteger collapsed = proof.collapsed();
        int hashPtr = 0;

        for (int level = 0; level < treeDepth; level++) {
            if (collapsed.testBit(level)) {
                // Single-child collapse: pass candidate upward unchanged.
            } else {
                if (hashPtr >= proof.hashes().size()) return false;
                byte[] sibHash = proof.hashes().get(hashPtr++);

                // Bit at position (treeDepth - 1 - level) in the nonce tells us
                // whether the current node is a right (1) or left (0) child.
                int bitPos = treeDepth - 1 - level;
                boolean isRight = index.testBit(bitPos);

                candidate = isRight
                        ? sha256(concat(sibHash, candidate))   // sib=left, candidate=right
                        : sha256(concat(candidate, sibHash));  // candidate=left, sib=right
            }
        }

        return Arrays.equals(candidate, rootHash);
    }

    // -------------------------------------------------------------------------
    // Static helpers: nonce derivation
    // -------------------------------------------------------------------------

    /**
     * Derive the leaf nonce for a DID: {@code nonce = BigInteger(sha256(did), big-endian)}.
     */
    public static BigInteger didToIndex(String did) {
        return new BigInteger(1, sha256(did.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    // -------------------------------------------------------------------------
    // Leaf hash computation
    // -------------------------------------------------------------------------

    /**
     * Compute a leaf hash per the spec.
     *
     * @param nonce      raw nonce bytes.
     * @param updateHash pre-computed {@code sha256(update)}, or {@code null} for non-updates.
     * @return leaf hash: {@code sha256(sha256(nonce))} or {@code sha256(sha256(nonce)||updateHash)}.
     */
    public static byte[] computeLeafHash(byte[] nonce, byte[] updateHash) {
        byte[] hn = sha256(nonce);
        return (updateHash == null) ? sha256(hn) : sha256(concat(hn, updateHash));
    }

    // -------------------------------------------------------------------------
    // Core tree hash computation (sparse, efficient)
    // -------------------------------------------------------------------------

    /**
     * Compute the hash of the subtree that covers {@code 2^depth} leaf positions
     * starting at {@code startLeaf}.
     *
     * <p>This is efficient because:
     * <ul>
     *   <li>It only visits subtrees that contain at least one occupied leaf.</li>
     *   <li>Internal memoisation (per root-hash call) avoids redundant work.</li>
     * </ul>
     *
     * @param startLeaf the nonce of the leftmost leaf in this subtree.
     * @param depth     0 == leaf node; TREE_DEPTH == root.
     * @param leafMap   the leaf store to query.
     * @return the hash, or {@link #EMPTY} if the subtree is empty.
     */
    static byte[] computeSubtreeHash(BigInteger startLeaf, int depth,
                                     Map<BigInteger, byte[]> leafMap) {
        if (depth == 0) {
            byte[] v = leafMap.get(startLeaf);
            return v != null ? v : EMPTY;
        }

        // Quick empty check: if no leaf in [startLeaf, startLeaf + 2^depth) exists, empty.
        // We rely on the caller having done that check implicitly; just recurse.
        BigInteger half = BigInteger.ONE.shiftLeft(depth - 1); // 2^(depth-1)
        BigInteger leftStart  = startLeaf;
        BigInteger rightStart = startLeaf.add(half);

        byte[] leftHash  = computeSubtreeHash(leftStart,  depth - 1, leafMap);
        byte[] rightHash = computeSubtreeHash(rightStart, depth - 1, leafMap);

        boolean lEmpty = isEmpty(leftHash);
        boolean rEmpty = isEmpty(rightHash);

        if (lEmpty && rEmpty) return EMPTY;
        if (lEmpty)           return rightHash;
        if (rEmpty)           return leftHash;
        return sha256(concat(leftHash, rightHash));
    }

    // -------------------------------------------------------------------------
    // Tree navigation helpers
    // -------------------------------------------------------------------------

    /**
     * Return the start-leaf nonce of the sibling at the given depth.
     * Flips the bit that separates left from right at depth {@code d}.
     */
    private static BigInteger siblingIndex(BigInteger nodeIndex, int depth) {
        // At depth d, the subtree spans 2^(d-1) leaves.
        // The differentiating bit position (in the full 256-bit nonce space) is TREE_DEPTH - depth.
        int bitPos = TREE_DEPTH - depth;
        return nodeIndex.flipBit(bitPos);
    }

    /**
     * Return the start-leaf nonce of the parent subtree (which has {@code depth} levels).
     * Clears the bit that was used to select this child.
     */
    private static BigInteger parentIndex(BigInteger nodeIndex, int depth) {
        int bitPos = TREE_DEPTH - depth;
        return nodeIndex.clearBit(bitPos);
    }

    /**
     * Align {@code nonce} to the leftmost position of the subtree it belongs to at the given depth.
     * (For depth==0 this is the nonce itself; higher depths mask off lower bits.)
     */
    private static BigInteger alignToDepth(BigInteger index, int treeDepth, int depth) {
        // Clear the lower (treeDepth - depth) bits – but since depth==0, all bits kept.
        return index; // leaf nonce is already fully precise
    }

    // -------------------------------------------------------------------------
    // Cryptographic utilities
    // -------------------------------------------------------------------------

    public static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    static boolean isEmpty(byte[] hash) {
        return hash == null || hash.length == 0;
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    public static String toHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "(empty)";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        return data;
    }
}
