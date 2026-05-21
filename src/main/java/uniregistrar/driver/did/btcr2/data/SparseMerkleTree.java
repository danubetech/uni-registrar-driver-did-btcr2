package uniregistrar.driver.did.btcr2.data;

import uniregistrar.driver.did.btcr2.util.SHA256Util;

import java.math.BigInteger;
import java.util.*;

/**
 * Optimized Sparse Merkle Tree (SMT) implementation.
 *
 * <p>Based on the did:btcr2 specification:
 * https://dcdpr.github.io/did-btcr2/appendix/optimized-smt.html
 *
 * <h2>Spec rules</h2>
 * <ul>
 *   <li>A node with two empty children is itself empty.</li>
 *   <li>A node with <em>one</em> non-empty child passes that child's hash upward unchanged
 *       (single-child collapsing / path compression).</li>
 *   <li>A node with two non-empty children: {@code sha256(left || right)}.</li>
 *   <li>Leaf value — update:    {@code sha256(sha256(index) || sha256(updateData))}</li>
 *   <li>Leaf value — non-update:{@code sha256(sha256(index))}</li>
 *   <li>Leaf index: {@code BigInteger(sha256(did), big-endian)}</li>
 * </ul>
 *
 * <h2>Efficiency</h2>
 * Leaves are stored in a {@link TreeMap} sorted by index.  Every subtree computation
 * begins with a {@link TreeMap#subMap} range query (O(log n)) to count how many
 * leaves fall within it:
 * <ul>
 *   <li><b>0 leaves</b> → return {@code EMPTY} immediately, no recursion.</li>
 *   <li><b>1 leaf</b> → return that leaf's pre-computed hash immediately (full
 *       collapse); the entire path from that leaf up to the subtree root vanishes
 *       in O(1).</li>
 *   <li><b>≥ 2 leaves</b> → split at the midpoint and recurse into the two halves.</li>
 * </ul>
 *
 * <p>The recursion therefore visits exactly the internal nodes where two populated
 * sub-branches diverge — at most {@code O(n)} such nodes for {@code n} leaves —
 * giving <b>O(n log n)</b> overall (dominated by the {@code log n} range-query cost
 * per node).  The 256-level depth is never fully traversed; it only affects the
 * maximum number of iterations when walking from a leaf up to the root in
 * {@link #generateProofForIndex} (at most 256 steps, each O(log n)).
 */
public class SparseMerkleTree {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /** SHA-256 → 256-bit digests → 2^256 addressable leaf positions. */
    public static final int TREE_DEPTH = 256;

    /**
     * Exclusive upper bound of the full index space: 2^256.
     * Used as the "end" sentinel in range queries.
     */
    private static final BigInteger FULL_SIZE = BigInteger.ONE.shiftLeft(TREE_DEPTH);

    /** Sentinel for an empty subtree (no occupied leaves). */
    static final byte[] EMPTY = new byte[0];

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /**
     * Leaf store, sorted by index.
     *
     * <p>A {@link TreeMap} is essential: it provides O(log n) {@code subMap} range
     * queries that let {@link #subtreeHash} determine in O(log n) whether a
     * half-subtree is empty or a single-leaf collapse, without descending into it.
     */
    private final TreeMap<BigInteger, byte[]> leaves = new TreeMap<>();

    // -------------------------------------------------------------------------
    // Public API – mutations
    // -------------------------------------------------------------------------

    /**
     * Insert a non-update entry for a DID.
     *
     * @param did   DID string; {@code sha256(did)} (big-endian) determines the leaf index.
     * @param nonce unique 256-bit index for this DID/signal combination (32 bytes).
     */
    public void insertNonUpdate(String did, byte[] nonce) {
        leaves.put(didToIndex(did), computeLeafHash(nonce, null));
    }

    /**
     * Insert an update entry for a DID.
     *
     * @param did        DID string.
     * @param nonce      unique 256-bit index (32 bytes).
     * @param updateData raw BTCR2 update payload (SHA-256 hashed internally).
     */
    public void insertUpdate(String did, byte[] nonce, byte[] updateData) {
        leaves.put(didToIndex(did), computeLeafHash(nonce, SHA256Util.sha256(updateData)));
    }
    public void insertUpdate(byte[] didIndex, byte[] nonce, byte[] updateData) {
        leaves.put(new BigInteger(1, didIndex), computeLeafHash(nonce, SHA256Util.sha256(updateData)));
    }
    public void insertUpdate(String did, byte[] updateHash) {
        leaves.put(didToIndex(did), updateHash);
    }
    public void insertUpdate(byte[] didIndex, byte[] updateHash) {
        leaves.put(new BigInteger(1, didIndex), updateHash);
    }

    /**
     * Insert a leaf at an explicit numeric index with a pre-computed leaf hash.
     * Intended for low-level tests and the 4-bit tree subclass.
     */
    public void insertLeafHash(BigInteger index, byte[] leafHash) {
        leaves.put(index, leafHash);
    }

    /** Remove a DID's leaf, marking its slot as empty. */
    public void remove(String did) {
        leaves.remove(didToIndex(did));
    }

    // -------------------------------------------------------------------------
    // Public API – queries
    // -------------------------------------------------------------------------

    /**
     * Compute and return the Merkle root hash of the current tree.
     *
     * @return the root hash, or {@link #EMPTY} if the tree has no leaves.
     */
    public byte[] rootHash() {
        return subtreeHash(BigInteger.ZERO, FULL_SIZE, leaves);
    }

    /**
     * Generate an {@link SMTProof} for the given DID.
     *
     * @param did DID to prove membership (or non-membership) for.
     * @return proof usable by a verifier to recompute the root hash.
     */
    public SMTProof generateProof(String did) {
        return generateProofForIndex(didToIndex(did));
    }

    /**
     * Generate an {@link SMTProof} for an explicit leaf index.
     *
     * <p>Walks from the leaf upward through 256 levels.  At each level it queries
     * the sibling subtree with a single O(log n) range check, so the total cost is
     * O(256 · log n) = O(n log n) in the worst case — far better than naïvely
     * recomputing the whole tree per level.
     *
     * @param index the leaf position (must be in [0, 2^256)).
     * @return the {@link SMTProof}.
     */
    public SMTProof generateProofForIndex(BigInteger index) {
        byte[] root = rootHash();
        List<byte[]> siblingHashes = new ArrayList<>();
        BigInteger collapsed = BigInteger.ZERO;

        // Walk upward one level at a time.
        // At each step:
        //   lo  = start of the current node's half-open range [lo, hi)
        //   hi  = end   of the current node's half-open range
        // The sibling is the other half of the parent range.
        // The spec's "collapsed bit from right" convention is LSB-first:
        // level 0 = one step above the leaf, level k = k steps above the leaf.
        // At level k, index.testBit(k) tells us whether we are the right (1) or left (0)
        // child of our parent — identical to the convention used in verifyProofWithDepth.
        //
        // We walk upward using half-open ranges [lo, hi) to avoid ever computing 2^256.
        BigInteger lo = index;                      // [index, index+1) — leaf range
        BigInteger hi = index.add(BigInteger.ONE);

        for (int level = 0; level < TREE_DEPTH; level++) {
            BigInteger rangeSize  = hi.subtract(lo);        // 2^level at this step
            BigInteger parentSize = rangeSize.shiftLeft(1); // 2^(level+1)

            // LSB-first: bit `level` of the index is 1 iff we are the RIGHT child.
            // Right child's range starts at parentLo + rangeSize; left child starts at parentLo.
            BigInteger parentLo = lo.clearBit(level); // clear bit `level` to get parent start

            BigInteger sibLo, sibHi;
            if (index.testBit(level)) {
                // We are the RIGHT child; sibling is the LEFT half [parentLo, lo)
                sibLo = parentLo;
                sibHi = lo;
            } else {
                // We are the LEFT child; sibling is the RIGHT half [hi, parentLo+parentSize)
                sibLo = hi;
                sibHi = parentLo.add(parentSize);
            }

            byte[] sibHash = subtreeHash(sibLo, sibHi, leaves);

            if (isEmpty(sibHash)) {
                // Sibling is empty → single-child collapse; candidate passes upward unchanged.
                collapsed = collapsed.setBit(level);
            } else {
                // Both sides non-empty → record sibling hash for the verifier.
                siblingHashes.add(sibHash);
            }

            // Move up to the parent range
            lo = parentLo;
            hi = parentLo.add(parentSize);
        }

        return new SMTProof(root, index, leaves.get(index), collapsed, siblingHashes);
    }
    public SMTProof generateProofForIndex(byte[] index) {
        return this.generateProofForIndex(new BigInteger(1, index));
    }

    // -------------------------------------------------------------------------
    // Proof verification (static – verifier side)
    // -------------------------------------------------------------------------

    /**
     * Verify an {@link SMTProof} against a known root hash.
     *
     * @param proof    the proof to verify.
     * @param rootHash the expected root hash (e.g. from a Beacon Signal).
     * @return {@code true} if the proof is valid.
     */
    public static boolean verifyProof(SMTProof proof, byte[] rootHash) {
        return verifyProofWithDepth(proof, rootHash, TREE_DEPTH);
    }

    /**
     * Verify a proof for a tree of the given depth.
     * Exposed package-private so the 4-bit test subclass can reuse it.
     */
    static boolean verifyProofWithDepth(SMTProof proof, byte[] rootHash, int treeDepth) {
        if (proof.updateId() == null || isEmpty(proof.updateId())) return false;

        BigInteger index     = proof.nonce();
        byte[]     candidate = proof.updateId().clone();
        BigInteger collapsed = proof.collapsed();
        int        hashPtr   = 0;

        for (int level = 0; level < treeDepth; level++) {
            if (collapsed.testBit(level)) {
                // Sibling was empty at this level; candidate passes through unchanged.
            } else {
                if (hashPtr >= proof.hashes().size()) return false;
                byte[] sibHash = proof.hashes().get(hashPtr++);

                // Level 0 = leaf level; the spec's "collapsed bit from right" convention
                // means level k corresponds to bit k from the LSB of the index.
                boolean isRight = index.testBit(level);
                candidate = isRight
                        ? SHA256Util.sha256(concat(sibHash, candidate))
                        : SHA256Util.sha256(concat(candidate, sibHash));
            }
        }

        return Arrays.equals(candidate, rootHash);
    }

    // -------------------------------------------------------------------------
    // Index derivation
    // -------------------------------------------------------------------------

    /**
     * Derive the leaf index for a DID string.
     * {@code index = BigInteger(sha256(UTF-8 bytes of did), big-endian, unsigned)}
     */
    public static BigInteger didToIndex(String did) {
        return new BigInteger(1, SHA256Util.sha256(did.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    // -------------------------------------------------------------------------
    // Leaf hash computation
    // -------------------------------------------------------------------------

    /**
     * Compute a leaf hash as per the spec.
     *
     * @param nonce      raw index bytes.
     * @param updateHash pre-computed {@code sha256(updateData)}, or {@code null} for non-updates.
     * @return {@code sha256(sha256(index))} or {@code sha256(sha256(index) || updateHash)}.
     */
    public static byte[] computeLeafHash(byte[] nonce, byte[] updateHash) {
        byte[] hn = SHA256Util.sha256(nonce);
        return (updateHash == null) ? SHA256Util.sha256(hn) : SHA256Util.sha256(concat(hn, updateHash));
    }

    // -------------------------------------------------------------------------
    // Core recursive hash — O(n log n)
    // -------------------------------------------------------------------------

    /**
     * Compute the hash of the subtree covering leaf indices in {@code [lo, hi)}.
     *
     * <h3>The three cases</h3>
     * <ol>
     *   <li>{@code subMap(lo, hi)} is <b>empty</b> → return {@link #EMPTY} immediately.</li>
     *   <li>{@code subMap(lo, hi)} has <b>exactly one entry</b> → return that leaf's hash
     *       immediately (the entire chain from leaf to subtree root collapses in O(1)).</li>
     *   <li>{@code subMap(lo, hi)} has <b>≥ 2 entries</b> → split at {@code mid = (lo+hi)/2}
     *       and recurse into {@code [lo, mid)} and {@code [mid, hi)}.</li>
     * </ol>
     *
     * <p>Case 1 and 2 are determined by a single {@link TreeMap#subMap} call, which is
     * O(log n).  Case 3 recurses, but only into subtrees that are known to contain leaves,
     * so the total number of recursive calls across the whole tree is O(n) — one per
     * internal node where two populated branches diverge.  Combined with the O(log n)
     * range-query cost per call, the overall complexity is <b>O(n log n)</b>.
     *
     * @param lo      inclusive start of the leaf-index range.
     * @param hi      exclusive end of the leaf-index range.
     * @param leafMap the sorted leaf store (must be a {@link NavigableMap}).
     * @return the subtree hash, or {@link #EMPTY} if the range is empty.
     */
    static byte[] subtreeHash(BigInteger lo, BigInteger hi,
                              NavigableMap<BigInteger, byte[]> leafMap) {
        // Range query: leaves in [lo, hi)
        NavigableMap<BigInteger, byte[]> sub = leafMap.subMap(lo, true, hi, false);

        switch (sub.size()) {
            case 0:
                // No leaves → empty subtree.
                return EMPTY;

            case 1:
                // Exactly one leaf → the entire subtree collapses to that leaf's hash
                // (every ancestor on the path has only one child, so it passes the value up).
                return sub.firstEntry().getValue();

            default:
                // Two or more leaves diverge somewhere below → must hash left || right.
                BigInteger mid = lo.add(hi).shiftRight(1); // (lo + hi) / 2
                byte[] leftHash  = subtreeHash(lo,  mid, leafMap);
                byte[] rightHash = subtreeHash(mid, hi,  leafMap);

                // Both sides non-empty (guaranteed by ≥2 leaves distributed across the split).
                // But one side might still be empty if all leaves land on one side by chance;
                // apply collapsing rules defensively.
                if (isEmpty(leftHash))  return rightHash;
                if (isEmpty(rightHash)) return leftHash;
                return SHA256Util.sha256(concat(leftHash, rightHash));
        }
    }

    // -------------------------------------------------------------------------
    // Cryptographic primitives
    // -------------------------------------------------------------------------

    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    static boolean isEmpty(byte[] hash) {
        return hash == null || hash.length == 0;
    }
}