package org.janus;

import java.util.Arrays;

/**
 * Keccak-f[1600] and the FIPS 202 sponge: SHA3-256, SHA3-512, SHAKE128 and SHAKE256.
 *
 * <p>Java 21 has SHA3-256 and SHA3-512 but no SHAKE, so the sponge is written here.
 * The JDK's SHA3 is used by the self-test to cross-check this permutation.
 */
final class Keccak {

    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
        0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
        0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L,
    };

    /** Rotation offsets, indexed by x + 5y. */
    private static final int[] ROT = {
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    };

    static final int SHAKE128_RATE = 168;
    static final int SHAKE256_RATE = 136;

    private static final byte SUFFIX_SHA3 = 0x06;
    private static final byte SUFFIX_SHAKE = 0x1F;

    static void permute(long[] a) {
        long[] c = new long[5];
        long[] b = new long[25];
        for (int round = 0; round < 24; round++) {
            for (int x = 0; x < 5; x++) {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) {
                    a[x + y] ^= d;
                }
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = Long.rotateLeft(a[x + 5 * y], ROT[x + 5 * y]);
                }
            }
            for (int y = 0; y < 25; y += 5) {
                for (int x = 0; x < 5; x++) {
                    a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
                }
            }
            a[0] ^= RC[round];
        }
    }

    // ---- Sponge -------------------------------------------------------------

    private final long[] state = new long[25];
    private final int rate;
    private final byte suffix;
    private int pos;
    private boolean squeezing;

    private Keccak(int rate, byte suffix) {
        this.rate = rate;
        this.suffix = suffix;
    }

    static Keccak shake128() {
        return new Keccak(SHAKE128_RATE, SUFFIX_SHAKE);
    }

    static Keccak shake256() {
        return new Keccak(SHAKE256_RATE, SUFFIX_SHAKE);
    }

    private void xorByte(int i, int v) {
        state[i >>> 3] ^= (long) (v & 0xFF) << (8 * (i & 7));
    }

    private int stateByte(int i) {
        return (int) (state[i >>> 3] >>> (8 * (i & 7))) & 0xFF;
    }

    Keccak absorb(byte[] data) {
        return absorb(data, 0, data.length);
    }

    Keccak absorb(byte[] data, int off, int len) {
        if (squeezing) {
            throw new IllegalStateException("absorb after squeeze");
        }
        for (int i = 0; i < len; i++) {
            xorByte(pos++, data[off + i]);
            if (pos == rate) {
                permute(state);
                pos = 0;
            }
        }
        return this;
    }

    void squeeze(byte[] out, int off, int len) {
        if (!squeezing) {
            xorByte(pos, suffix);
            xorByte(rate - 1, 0x80);
            permute(state);
            pos = 0;
            squeezing = true;
        }
        for (int i = 0; i < len; i++) {
            if (pos == rate) {
                permute(state);
                pos = 0;
            }
            out[off + i] = (byte) stateByte(pos++);
        }
    }

    byte[] squeeze(int len) {
        byte[] out = new byte[len];
        squeeze(out, 0, len);
        return out;
    }

    void wipe() {
        Arrays.fill(state, 0L);
    }

    // ---- One-shot functions -------------------------------------------------

    static byte[] shake128(byte[] in, int outLen) {
        return shake128().absorb(in).squeeze(outLen);
    }

    static byte[] shake256(byte[] in, int outLen) {
        return shake256().absorb(in).squeeze(outLen);
    }

    /** SHA3-256 through this sponge (the format uses the JDK's; this one is for cross-checks). */
    static byte[] sha3_256(byte[] in) {
        return new Keccak(136, SUFFIX_SHA3).absorb(in).squeeze(32);
    }

    /** SHA3-512 through this sponge (the format uses the JDK's; this one is for cross-checks). */
    static byte[] sha3_512(byte[] in) {
        return new Keccak(72, SUFFIX_SHA3).absorb(in).squeeze(64);
    }
}
