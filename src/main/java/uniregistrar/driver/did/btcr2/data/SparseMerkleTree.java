package uniregistrar.driver.did.btcr2.data;

import uniregistrar.driver.did.btcr2.util.SHA256Util;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class SparseMerkleTree {

    private static final int TREE_DEPTH = 256;

    private final Map<NodeKey, byte[]> nodes = new HashMap<>();
    private final byte[][] defaultHashes = new byte[TREE_DEPTH + 1][];

    private byte[] root;

    public SparseMerkleTree() {
        buildDefaultHashes();
        this.root = this.defaultHashes[TREE_DEPTH];
    }

    public void put(byte[] key, byte[] value) {
        byte[] path = SHA256Util.sha256(key);
        byte[] currentHash = leafHash(key, value);

        NodeKey leafKey = new NodeKey(TREE_DEPTH, path);
        this.nodes.put(leafKey, currentHash);

        for (int depth=TREE_DEPTH-1; depth>=0; depth--) {
            boolean bit = getBit(path, depth);
            byte[] siblingHash;

            NodeKey siblingKey = new NodeKey(depth + 1, siblingPath(path, depth));
            siblingHash = this.nodes.getOrDefault(siblingKey, defaultHashes[depth]);
            byte[] left, right;
            if (! bit) {
                left = currentHash;
                right = siblingHash;
            } else {
                left = siblingHash;
                right = currentHash;
            }

            currentHash = internalHash(left, right);
            NodeKey parentKey = new NodeKey(depth, truncatePath(path, depth));
            this.nodes.put(parentKey, currentHash);
        }

        this.root = currentHash;
    }

    public Proof generateProof(byte[] key) {
        byte[] path = SHA256Util.sha256(key);
        byte[][] siblings = new byte[TREE_DEPTH][];

        for (int depth = TREE_DEPTH - 1; depth >= 0; depth--) {
            NodeKey siblingKey = new NodeKey(depth + 1, siblingPath(path, depth));
            siblings[TREE_DEPTH - 1 - depth] = nodes.getOrDefault(siblingKey, defaultHashes[depth]);
        }

        return new Proof(siblings);
    }

    public static boolean verifyProof(byte[] root, byte[] key, byte[] value, Proof proof) {
        byte[] path = SHA256Util.sha256(key);
        byte[] hash = leafHash(key, value);

        for (int depth = TREE_DEPTH - 1; depth >= 0; depth--) {
            byte[] sibling = proof.siblings[TREE_DEPTH - 1 - depth];
            boolean bit = getBit(path, depth);
            if (! bit) {
                hash = internalHash(hash, sibling);
            } else {
                hash = internalHash(sibling, hash);
            }
        }

        return Arrays.equals(hash, root);
    }

    /*
     * Helper methods
     */

    private void buildDefaultHashes() {
        this.defaultHashes[0] = SHA256Util.sha256(new byte[]{0});
        for (int i=1; i<=TREE_DEPTH; i++) {
            this.defaultHashes[i] = internalHash(this.defaultHashes[i-1], this.defaultHashes[i-1]);
        }
    }

    private static byte[] leafHash(byte[] key, byte[] value) {
        ByteBuffer buffer = ByteBuffer.allocate(1 + key.length + value.length);
        buffer.put((byte) 0x00);
        buffer.put(key);
        buffer.put(value);
        return SHA256Util.sha256(buffer.array());
    }

    private static byte[] internalHash(byte[] left, byte[] right) {
        ByteBuffer buffer = ByteBuffer.allocate(left.length + right.length);
        buffer.put(left);
        buffer.put(right);
        return SHA256Util.sha256(buffer.array());
    }

    private static boolean getBit(byte[] bytes, int index) {
        int byteIndex = index / 8;
        int bitIndex = 7 - (index % 8);
        return ((bytes[byteIndex] >> bitIndex) & 1) == 1;
    }

    private static byte[] truncatePath(byte[] path, int depth) {
        byte[] copy = Arrays.copyOf(path, path.length);
        int bitsToKeep = depth;
        for (int i = bitsToKeep; i < TREE_DEPTH; i++) {
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);
            copy[byteIndex] &= ~(1 << bitIndex);
        }
        return copy;
    }

    private static byte[] siblingPath(byte[] path, int depth) {
        byte[] copy = truncatePath(path, depth + 1);
        int bitIndex = depth;
        int byteIndex = bitIndex / 8;
        int offset = 7 - (bitIndex % 8);
        copy[byteIndex] ^= (1 << offset);
        return copy;
    }

    /*
     * Getters
     */

    public byte[] getRoot() {
        return this.root;
    }

    /*
     * Helper classes
     */

    public static class Proof {
        public final byte[][] siblings;

        public Proof(byte[][] siblings) {
            this.siblings = siblings;
        }
    }

    private static class NodeKey {
        final int depth;
        final byte[] path;

        NodeKey(int depth, byte[] path) {
            this.depth = depth;
            this.path = path;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            NodeKey nodeKey = (NodeKey) o;
            return depth == nodeKey.depth && Objects.deepEquals(path, nodeKey.path);
        }

        @Override
        public int hashCode() {
            return Objects.hash(depth, Arrays.hashCode(path));
        }
    }
}