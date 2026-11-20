package org.janus;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Argon2id, version 0x13 (RFC 9106). The lanes of each slice run in parallel threads.
 *
 * <p>Janus uses {@link #janus}: 65 536 KiB, 3 passes, parallelism 4, 32-byte output.
 */
final class Argon2id {

    private static final int VERSION = 0x13;
    private static final int TYPE_ID = 2;
    private static final int SYNC_POINTS = 4;
    private static final int BLOCK_WORDS = 128;      // 1024-byte blocks as 64-bit words

    private Argon2id() {
    }

    /** The format's {@code Argon2id(pw, salt)} (spec 2.1). */
    static byte[] janus(byte[] password, byte[] salt) {
        return hash(password, salt, new byte[0], new byte[0], 65536, 3, 4, 32);
    }

    static byte[] hash(byte[] password, byte[] salt, byte[] secret, byte[] ad,
                       int memoryKiB, int passes, int lanes, int tagLength) {
        // H0
        Blake2b b = new Blake2b(64);
        b.updateLe32(lanes).updateLe32(tagLength).updateLe32(memoryKiB).updateLe32(passes)
         .updateLe32(VERSION).updateLe32(TYPE_ID);
        b.updateLe32(password.length).update(password);
        b.updateLe32(salt.length).update(salt);
        b.updateLe32(secret.length).update(secret);
        b.updateLe32(ad.length).update(ad);
        byte[] h0 = b.digest();

        int segmentLength = memoryKiB / (SYNC_POINTS * lanes);
        int laneLength = segmentLength * SYNC_POINTS;
        int blockCount = laneLength * lanes;
        long[] memory = new long[blockCount * BLOCK_WORDS];
        Instance inst = new Instance(memory, lanes, laneLength, segmentLength, blockCount, passes);

        // First two blocks of every lane.
        for (int l = 0; l < lanes; l++) {
            for (int j = 0; j < 2; j++) {
                byte[] block = hPrime(Bytes.concat(h0, le32(j), le32(l)), 1024);
                loadBlock(memory, (l * laneLength + j) * BLOCK_WORDS, block);
                Arrays.fill(block, (byte) 0);
            }
        }
        Arrays.fill(h0, (byte) 0);

        ExecutorService pool = lanes > 1 ? Executors.newFixedThreadPool(lanes, r -> {
            Thread t = new Thread(r, "argon2-lane");
            t.setDaemon(true);
            return t;
        }) : null;
        try {
            for (int pass = 0; pass < passes; pass++) {
                for (int slice = 0; slice < SYNC_POINTS; slice++) {
                    if (pool == null) {
                        inst.fillSegment(pass, 0, slice);
                        continue;
                    }
                    List<Future<?>> jobs = new ArrayList<>();
                    for (int l = 0; l < lanes; l++) {
                        final int lane = l, p = pass, s = slice;
                        jobs.add(pool.submit(() -> inst.fillSegment(p, lane, s)));
                    }
                    for (Future<?> f : jobs) {
                        f.get();
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Argon2id interrupted", e);
        } catch (ExecutionException e) {
            throw new IllegalStateException("Argon2id failed", e.getCause());
        } finally {
            if (pool != null) {
                pool.shutdownNow();
            }
        }

        // Final block: XOR of the last column.
        long[] last = new long[BLOCK_WORDS];
        for (int l = 0; l < lanes; l++) {
            int off = (l * laneLength + laneLength - 1) * BLOCK_WORDS;
            for (int i = 0; i < BLOCK_WORDS; i++) {
                last[i] ^= memory[off + i];
            }
        }
        Arrays.fill(memory, 0L);
        byte[] lastBytes = storeBlock(last);
        Arrays.fill(last, 0L);
        byte[] tag = hPrime(lastBytes, tagLength);
        Arrays.fill(lastBytes, (byte) 0);
        return tag;
    }

    private static final class Instance {
        final long[] memory;
        final int lanes, laneLength, segmentLength, blockCount, passes;

        Instance(long[] memory, int lanes, int laneLength, int segmentLength, int blockCount, int passes) {
            this.memory = memory;
            this.lanes = lanes;
            this.laneLength = laneLength;
            this.segmentLength = segmentLength;
            this.blockCount = blockCount;
            this.passes = passes;
        }

        void fillSegment(int pass, int lane, int slice) {
            long[] r = new long[BLOCK_WORDS];
            long[] tmp = new long[BLOCK_WORDS];
            boolean dataIndependent = pass == 0 && slice < SYNC_POINTS / 2;
            long[] zero = null, input = null, address = null;
            if (dataIndependent) {
                zero = new long[BLOCK_WORDS];
                input = new long[BLOCK_WORDS];
                address = new long[BLOCK_WORDS];
                input[0] = pass;
                input[1] = lane;
                input[2] = slice;
                input[3] = blockCount;
                input[4] = passes;
                input[5] = TYPE_ID;
            }
            int start = 0;
            if (pass == 0 && slice == 0) {
                start = 2;
                if (dataIndependent) {
                    nextAddresses(zero, input, address, r, tmp);
                }
            }
            int curr = lane * laneLength + slice * segmentLength + start;
            int prev = (curr % laneLength == 0) ? curr + laneLength - 1 : curr - 1;
            for (int i = start; i < segmentLength; i++, curr++, prev++) {
                if (curr % laneLength == 1) {
                    prev = curr - 1;
                }
                long pseudoRand;
                if (dataIndependent) {
                    if (i % BLOCK_WORDS == 0) {
                        nextAddresses(zero, input, address, r, tmp);
                    }
                    pseudoRand = address[i % BLOCK_WORDS];
                } else {
                    pseudoRand = memory[prev * BLOCK_WORDS];
                }
                int refLane = (int) Long.remainderUnsigned(pseudoRand >>> 32, lanes);
                if (pass == 0 && slice == 0) {
                    refLane = lane;
                }
                int refIndex = indexAlpha(pass, slice, i, pseudoRand & 0xFFFFFFFFL, refLane == lane);
                int ref = refLane * laneLength + refIndex;
                fillBlock(memory, prev * BLOCK_WORDS, memory, ref * BLOCK_WORDS,
                          memory, curr * BLOCK_WORDS, pass != 0, r, tmp);
            }
        }

        private int indexAlpha(int pass, int slice, int index, long j1, boolean sameLane) {
            long area;
            if (pass == 0) {
                if (slice == 0) {
                    area = index - 1;
                } else if (sameLane) {
                    area = (long) slice * segmentLength + index - 1;
                } else {
                    area = (long) slice * segmentLength + (index == 0 ? -1 : 0);
                }
            } else {
                if (sameLane) {
                    area = laneLength - segmentLength + index - 1;
                } else {
                    area = laneLength - segmentLength + (index == 0 ? -1 : 0);
                }
            }
            long rel = (j1 * j1) >>> 32;
            rel = area - 1 - ((area * rel) >>> 32);
            long startPos = 0;
            if (pass != 0) {
                startPos = (slice == SYNC_POINTS - 1) ? 0 : (long) (slice + 1) * segmentLength;
            }
            return (int) ((startPos + rel) % laneLength);
        }

        private static void nextAddresses(long[] zero, long[] input, long[] address, long[] r, long[] tmp) {
            input[6]++;
            fillBlock(zero, 0, input, 0, address, 0, false, r, tmp);
            fillBlock(zero, 0, address, 0, address, 0, false, r, tmp);
        }
    }

    /** The compression function G, written into {@code out}; with {@code xor}, XORed into it. */
    private static void fillBlock(long[] x, int xo, long[] y, int yo, long[] out, int oo,
                                  boolean xor, long[] r, long[] tmp) {
        for (int i = 0; i < BLOCK_WORDS; i++) {
            r[i] = x[xo + i] ^ y[yo + i];
            tmp[i] = xor ? r[i] ^ out[oo + i] : r[i];
        }
        for (int i = 0; i < 8; i++) {          // rows
            int o = 16 * i;
            permute(r, o, o + 1, o + 2, o + 3, o + 4, o + 5, o + 6, o + 7,
                    o + 8, o + 9, o + 10, o + 11, o + 12, o + 13, o + 14, o + 15);
        }
        for (int i = 0; i < 8; i++) {          // columns
            int o = 2 * i;
            permute(r, o, o + 1, o + 16, o + 17, o + 32, o + 33, o + 48, o + 49,
                    o + 64, o + 65, o + 80, o + 81, o + 96, o + 97, o + 112, o + 113);
        }
        for (int i = 0; i < BLOCK_WORDS; i++) {
            out[oo + i] = tmp[i] ^ r[i];
        }
    }

    private static void permute(long[] v, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7,
                                int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15) {
        gb(v, v0, v4, v8, v12);
        gb(v, v1, v5, v9, v13);
        gb(v, v2, v6, v10, v14);
        gb(v, v3, v7, v11, v15);
        gb(v, v0, v5, v10, v15);
        gb(v, v1, v6, v11, v12);
        gb(v, v2, v7, v8, v13);
        gb(v, v3, v4, v9, v14);
    }

    private static long fBlaMka(long x, long y) {
        return x + y + 2 * (x & 0xFFFFFFFFL) * (y & 0xFFFFFFFFL);
    }

    private static void gb(long[] v, int a, int b, int c, int d) {
        v[a] = fBlaMka(v[a], v[b]);
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = fBlaMka(v[c], v[d]);
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = fBlaMka(v[a], v[b]);
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = fBlaMka(v[c], v[d]);
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }

    /** The variable-length hash H' of RFC 9106, section 3.3. */
    static byte[] hPrime(byte[] x, int t) {
        if (t <= 64) {
            return new Blake2b(t).updateLe32(t).update(x).digest();
        }
        int r = (t + 31) / 32 - 2;
        byte[] out = new byte[t];
        byte[] v = new Blake2b(64).updateLe32(t).update(x).digest();
        System.arraycopy(v, 0, out, 0, 32);
        for (int i = 1; i < r; i++) {
            v = Blake2b.hash(v, 64);
            System.arraycopy(v, 0, out, 32 * i, 32);
        }
        byte[] lastV = Blake2b.hash(v, t - 32 * r);
        System.arraycopy(lastV, 0, out, 32 * r, lastV.length);
        Arrays.fill(v, (byte) 0);
        Arrays.fill(lastV, (byte) 0);
        return out;
    }

    private static byte[] le32(int x) {
        return new byte[] {(byte) x, (byte) (x >>> 8), (byte) (x >>> 16), (byte) (x >>> 24)};
    }

    private static void loadBlock(long[] mem, int off, byte[] block) {
        for (int i = 0; i < BLOCK_WORDS; i++) {
            long w = 0;
            for (int j = 7; j >= 0; j--) {
                w = (w << 8) | (block[8 * i + j] & 0xFF);
            }
            mem[off + i] = w;
        }
    }

    private static byte[] storeBlock(long[] block) {
        byte[] out = new byte[BLOCK_WORDS * 8];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (block[i >>> 3] >>> (8 * (i & 7)));
        }
        return out;
    }
}
