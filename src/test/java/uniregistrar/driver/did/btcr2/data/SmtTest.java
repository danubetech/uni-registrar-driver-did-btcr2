package uniregistrar.driver.did.btcr2.data;

import org.apache.commons.codec.binary.Hex;
import uniregistrar.driver.did.btcr2.util.SHA256Util;

import java.math.BigInteger;
import java.util.*;

/**
 * Test suite for {@link SparseMerkleTree}.
 *
 * Uses a 4-bit tree subclass to reproduce the worked example from the spec,
 * then exercises the full 256-bit tree.
 */
public class SmtTest {

    // -------------------------------------------------------------------------
    // 4-bit tree — reproduces the spec example exactly
    // -------------------------------------------------------------------------

    /**
     * A Sparse Merkle Tree whose index space is 4 bits (leaves 0–15).
     *
     * The full index space is [0, 16) instead of [0, 2^256).
     * We reuse the parent's {@link SparseMerkleTree#subtreeHash} method directly,
     * just with a different FULL_SIZE.
     */
    static class SmtTree4 extends SparseMerkleTree {

        private static final BigInteger SIZE4 = BigInteger.valueOf(16); // 2^4

        void insertAt(int index, byte[] leafHash) {
            insertLeafHash(BigInteger.valueOf(index), leafHash);
        }

        byte[] root4() {
            // Expose the internal leaves field via a thin helper
            return subtreeHash(BigInteger.ZERO, SIZE4, leaves());
        }

        /** Hash of the subtree covering [lo, hi) in the 4-bit space. */
        byte[] node4(BigInteger lo, BigInteger hi) {
            return subtreeHash(lo, hi, leaves());
        }

        SMTProof generateProof4(int index) {
            BigInteger idx = BigInteger.valueOf(index);
            byte[] root = root4();
            List<byte[]> siblingHashes = new ArrayList<>();
            BigInteger collapsed = BigInteger.ZERO;

            BigInteger lo = idx;
            BigInteger hi = idx.add(BigInteger.ONE);

            for (int level = 0; level < 4; level++) {
                BigInteger parentSize = BigInteger.ONE.shiftLeft(level + 1);
                BigInteger parentLo   = lo.clearBit(level);

                BigInteger sibLo, sibHi;
                if (idx.testBit(level)) {
                    sibLo = parentLo; sibHi = lo;   // right child → sibling is left half
                } else {
                    sibLo = hi; sibHi = parentLo.add(parentSize); // left child → sibling is right half
                }

                byte[] sibHash = subtreeHash(sibLo, sibHi, leaves());
                if (isEmpty(sibHash)) {
                    collapsed = collapsed.setBit(level);
                } else {
                    siblingHashes.add(sibHash);
                }

                lo = parentLo;
                hi = parentLo.add(parentSize);
            }

            return new SMTProof(root, idx, leaves().get(idx), collapsed, siblingHashes);
        }

        static boolean verify4(SMTProof proof, byte[] rootHash) {
            return verifyProofWithDepth(proof, rootHash, 4);
        }

        /** Expose the internal TreeMap for use in this subclass. */
        java.util.NavigableMap<BigInteger, byte[]> leaves() {
            // We replicate it here since we can't access the private field directly.
            // Instead, override insertLeafHash to build our own.
            return _leaves;
        }

        private final java.util.TreeMap<BigInteger, byte[]> _leaves = new java.util.TreeMap<>();

        @Override
        public void insertLeafHash(BigInteger index, byte[] leafHash) {
            super.insertLeafHash(index, leafHash);
            _leaves.put(index, leafHash);
        }
    }

    // -------------------------------------------------------------------------
    // Test runner
    // -------------------------------------------------------------------------

    static int passed = 0;
    static int failed = 0;

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("  Sparse Merkle Tree – Test Suite");
        System.out.println("========================================");

        testEmptyTree();
        testSingleLeaf();
        testSpecExampleSubtrees();
        testProofVerification();
        testNonMembershipProof();
        test256BitTree();
        testRootChangesOnInsert();
        testRemoveLeaf();
        testLeafHashComputation();
        testInsertionOrderIndependence();
        testLargeTree();

        System.out.println("\n========================================");
        System.out.printf("  Results: %d passed, %d failed%n", passed, failed);
        System.out.println("========================================");
        if (failed > 0) System.exit(1);
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    static void testEmptyTree() {
        section("Empty tree");
        SparseMerkleTree smt = new SparseMerkleTree();
        assertTrue("Empty tree root is EMPTY", SparseMerkleTree.isEmpty(smt.rootHash()));
    }

    static void testSingleLeaf() {
        section("Single leaf collapses to its own hash");
        SmtTree4 smt = new SmtTree4();
        byte[] leafHash = SHA256Util.sha256("hello".getBytes());
        smt.insertAt(5, leafHash);

        byte[] root = smt.root4();
        assertFalse("Root not empty", SparseMerkleTree.isEmpty(root));
        assertTrue("Single leaf: root == leaf (full collapse)", Arrays.equals(root, leafHash));
    }

    static void testSpecExampleSubtrees() {
        section("Spec example: 4-bit tree with indices 0,2,5,9,13,14");

        SmtTree4 smt = buildSpecTree();
        byte[] h0  = smt._leaves.get(bi(0));
        byte[] h2  = smt._leaves.get(bi(2));
        byte[] h5  = smt._leaves.get(bi(5));
        byte[] h9  = smt._leaves.get(bi(9));
        byte[] h13 = smt._leaves.get(bi(13));
        byte[] h14 = smt._leaves.get(bi(14));

        // Hash 00 = hash(h0 || h2)  — both occupied, no collapse
        byte[] hash00 = sha256(concat(h0, h2));
        assertEq("Hash[0,4) == hash(h0||h2)", hash00, smt.node4(bi(0), bi(4)));

        // Hash 01 — only index 5 (=0101), so collapses to h5
        assertEq("Hash[4,8) collapses to h5", h5, smt.node4(bi(4), bi(8)));

        // Hash 0 = hash(hash00 || h5)
        byte[] hash0 = sha256(concat(hash00, h5));
        assertEq("Hash[0,8) == hash(hash00||h5)", hash0, smt.node4(bi(0), bi(8)));

        // Hash 10 — only index 9 (=1001), collapses to h9
        assertEq("Hash[8,12) collapses to h9", h9, smt.node4(bi(8), bi(12)));

        // Hash 11 = hash(h13 || h14)
        byte[] hash11 = sha256(concat(h13, h14));
        assertEq("Hash[12,16) == hash(h13||h14)", hash11, smt.node4(bi(12), bi(16)));

        // Hash 1 = hash(h9 || hash11)
        byte[] hash1 = sha256(concat(h9, hash11));
        assertEq("Hash[8,16) == hash(h9||hash11)", hash1, smt.node4(bi(8), bi(16)));

        // Root = hash(hash0 || hash1)
        byte[] expectedRoot = sha256(concat(hash0, hash1));
        assertEq("Root == hash(hash0||hash1)", expectedRoot, smt.root4());

        System.out.println("  root = " + Hex.encodeHexString(smt.root4()));
    }

    static void testProofVerification() {
        section("Proof generation and verification (index 13)");

        SmtTree4 smt = buildSpecTree();
        SMTProof proof = smt.generateProof4(13);
        System.out.println("  " + proof.toString());

        assertTrue("Proof for index 13 verifies", SmtTree4.verify4(proof, smt.root4()));

        // Tamper: flip a byte in the leaf hash
        byte[] tampered = proof.getUpdateId().clone();
        tampered[0] ^= 0xFF;
        SMTProof bad = new SMTProof(proof.getId(), proof.getNonce(), tampered,
                proof.getCollapsed(), proof.getHashes());
        assertFalse("Tampered proof must NOT verify", SmtTree4.verify4(bad, smt.root4()));

        // Verify all leaves in the spec tree
        for (int idx : new int[]{0, 2, 5, 9, 13, 14}) {
            SMTProof p = smt.generateProof4(idx);
            assertTrue("Proof for index " + idx + " verifies", SmtTree4.verify4(p, smt.root4()));
        }
    }

    static void testNonMembershipProof() {
        section("Non-member proof returns false");
        SmtTree4 smt = buildSpecTree();
        SMTProof proof = smt.generateProof4(7); // not in tree
        assertFalse("Non-member proof must not verify", SmtTree4.verify4(proof, smt.root4()));
    }

    static void test256BitTree() {
        section("256-bit tree: DID insertion, root determinism, proof round-trip");

        SparseMerkleTree smt1 = new SparseMerkleTree();
        SparseMerkleTree smt2 = new SparseMerkleTree();

        String didA = "did:example:alice";
        String didB = "did:example:bob";
        byte[] nonceA = sha256("index-alice".getBytes());
        byte[] nonceB = sha256("index-bob".getBytes());
        byte[] updateB = sha256("update-bob".getBytes());

        smt1.insertNonUpdate(didA, nonceA);
        smt1.insertUpdate(didB, nonceB, updateB);

        smt2.insertUpdate(didB, nonceB, updateB);   // reversed insertion order
        smt2.insertNonUpdate(didA, nonceA);

        assertEq("Insertion order must not affect root", smt1.rootHash(), smt2.rootHash());
        System.out.println("  root = " + Hex.encodeHexString(smt1.rootHash()));

        SMTProof pA = smt1.generateProof(didA);
        assertTrue("Proof for alice verifies", SparseMerkleTree.verifyProof(pA, smt1.rootHash()));

        SMTProof pB = smt1.generateProof(didB);
        assertTrue("Proof for bob (update) verifies", SparseMerkleTree.verifyProof(pB, smt1.rootHash()));
    }

    static void testRootChangesOnInsert() {
        section("Root changes after each insert");
        SparseMerkleTree smt = new SparseMerkleTree();
        smt.insertNonUpdate("did:example:x", sha256("nx".getBytes()));
        byte[] root1 = smt.rootHash().clone();
        smt.insertNonUpdate("did:example:y", sha256("ny".getBytes()));
        assertFalse("Root changed after second insert", Arrays.equals(root1, smt.rootHash()));
    }

    static void testRemoveLeaf() {
        section("Remove leaf restores previous root");
        SparseMerkleTree smt = new SparseMerkleTree();
        smt.insertNonUpdate("did:example:alice", sha256("index-alice".getBytes()));
        byte[] root1 = smt.rootHash().clone();
        smt.insertNonUpdate("did:example:bob", sha256("index-bob".getBytes()));
        smt.remove("did:example:bob");
        assertEq("Root restored after remove", root1, smt.rootHash());
    }

    static void testLeafHashComputation() {
        section("Leaf hash formulas");
        byte[] nonce  = sha256("test-index".getBytes());
        byte[] update = sha256("update-data".getBytes());

        byte[] nonUpdate = SparseMerkleTree.computeLeafHash(nonce, null);
        byte[] withUpdate = SparseMerkleTree.computeLeafHash(nonce, update);

        assertFalse("Non-update ≠ update leaf hash", Arrays.equals(nonUpdate, withUpdate));
        assertEq("Non-update: sha256(sha256(index))",
                sha256(sha256(nonce)), nonUpdate);
        assertEq("Update: sha256(sha256(index)||updateHash)",
                sha256(concat(sha256(nonce), update)), withUpdate);
    }

    static void testInsertionOrderIndependence() {
        section("Root is order-independent for many DIDs");
        String[] dids = {"did:a", "did:b", "did:c", "did:d", "did:e"};
        byte[][] nonces = new byte[dids.length][];
        for (int i = 0; i < dids.length; i++) nonces[i] = sha256(("index" + i).getBytes());

        SparseMerkleTree base = new SparseMerkleTree();
        for (int i = 0; i < dids.length; i++) base.insertNonUpdate(dids[i], nonces[i]);
        byte[] baseRoot = base.rootHash();

        // Insert in reverse order
        SparseMerkleTree rev = new SparseMerkleTree();
        for (int i = dids.length - 1; i >= 0; i--) rev.insertNonUpdate(dids[i], nonces[i]);
        assertEq("Reversed insertion gives same root", baseRoot, rev.rootHash());

        // Insert in shuffled order
        List<Integer> order = new ArrayList<>(Arrays.asList(2, 4, 0, 3, 1));
        SparseMerkleTree shuf = new SparseMerkleTree();
        for (int i : order) shuf.insertNonUpdate(dids[i], nonces[i]);
        assertEq("Shuffled insertion gives same root", baseRoot, shuf.rootHash());
    }

    static void testLargeTree() {
        section("Performance: 10,000 DIDs, root + all proofs");
        int N = 10_000;
        SparseMerkleTree smt = new SparseMerkleTree();
        String[] dids = new String[N];
        for (int i = 0; i < N; i++) {
            dids[i] = "did:example:" + i;
            smt.insertNonUpdate(dids[i], sha256(("index" + i).getBytes()));
        }
        long t0 = System.currentTimeMillis();
        byte[] root = smt.rootHash();
        long rootTime = System.currentTimeMillis() - t0;
        assertFalse("Root is non-empty for large tree", SparseMerkleTree.isEmpty(root));
        System.out.println("  rootHash (" + N + " leaves): " + rootTime + " ms");

        // Verify proofs for first 100 leaves
        long t1 = System.currentTimeMillis();
        int verified = 0;
        for (int i = 0; i < 100; i++) {
            SMTProof p = smt.generateProof(dids[i]);
            if (SparseMerkleTree.verifyProof(p, root)) verified++;
        }
        long proofTime = System.currentTimeMillis() - t1;
        assertTrue("All 100 sample proofs verify", verified == 100);
        System.out.println("  100 proofs generated+verified: " + proofTime + " ms");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    static SmtTree4 buildSpecTree() {
        SmtTree4 smt = new SmtTree4();
        byte[] h0  = SparseMerkleTree.computeLeafHash(sha256("index-0000".getBytes()), null);
        byte[] h2  = SparseMerkleTree.computeLeafHash(sha256("index-0010".getBytes()),
                sha256("data-0010".getBytes()));
        byte[] h5  = SparseMerkleTree.computeLeafHash(sha256("index-0101".getBytes()), null);
        byte[] h9  = SparseMerkleTree.computeLeafHash(sha256("index-1001".getBytes()),
                sha256("data-1001".getBytes()));
        byte[] h13 = SparseMerkleTree.computeLeafHash(sha256("index-1101".getBytes()),
                sha256("data-1101".getBytes()));
        byte[] h14 = SparseMerkleTree.computeLeafHash(sha256("index-1110".getBytes()), null);
        smt.insertAt(0,  h0);
        smt.insertAt(2,  h2);
        smt.insertAt(5,  h5);
        smt.insertAt(9,  h9);
        smt.insertAt(13, h13);
        smt.insertAt(14, h14);
        return smt;
    }

    static BigInteger bi(int v) { return BigInteger.valueOf(v); }
    static byte[] sha256(byte[] b) { return SHA256Util.sha256(b); }
    static byte[] concat(byte[] a, byte[] b) { return SparseMerkleTree.concat(a, b); }

    static void section(String name) { System.out.println("\n--- " + name + " ---"); }

    static void assertTrue(String msg, boolean cond) {
        System.out.println("  " + (cond ? "PASS" : "FAIL") + ": " + msg);
        if (cond) passed++; else failed++;
    }
    static void assertFalse(String msg, boolean cond) { assertTrue(msg, !cond); }
    static void assertEq(String msg, byte[] a, byte[] b) {
        assertTrue(msg, java.util.Arrays.equals(a, b));
    }
}