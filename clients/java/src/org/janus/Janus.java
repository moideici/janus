package org.janus;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** The Janus v1 file format: sizes and layout (spec 6), encryption (7) and decryption (8). */
final class Janus {

    static final int N_SLOTS = 16;
    static final int N_TAGS = 4;
    static final int S = 1632;
    static final int H = 32 * N_TAGS + 32 + N_SLOTS * S;       // 26 272
    static final int TB = 65536;
    static final long R_MIN = 65536;
    static final long RHO = 16;

    private static final int SALT_OFF = 32 * N_TAGS;            // 128
    private static final int SLOTS_OFF = SALT_OFF + 32;         // 160
    private static final int W_OFF = 1568;                      // wrap offset inside a slot
    private static final int WRAP_PLAIN = 48;

    private static final byte[] LABEL_HEADER = Bytes.ascii("janus/v1/entete");
    private static final byte[] LABEL_BODY = Bytes.ascii("janus/v1/corps");
    private static final byte[] LABEL_WRAP_XWING = Bytes.ascii("janus/v1/emballage/xwing");
    private static final byte[] LABEL_WRAP_PASSWORD = Bytes.ascii("janus/v1/emballage/mdp");
    private static final byte[] ZERO_NONCE = new byte[12];

    private Janus() {
    }

    /** One face to encrypt: a plaintext and either one password or 1 to 16 public keys. */
    record Face(byte[] plaintext, byte[] password, List<byte[]> publicKeys) {
        static Face withPassword(byte[] plaintext, byte[] password) {
            return new Face(plaintext, password, List.of());
        }

        static Face withKeys(byte[] plaintext, List<byte[]> publicKeys) {
            return new Face(plaintext, null, List.copyOf(publicKeys));
        }

        int recipients() {
            return (password != null ? 1 : 0) + publicKeys.size();
        }
    }

    /** Errors. {@link Kind#CANNOT_DECRYPT} is deliberately uninformative. */
    static final class JanusException extends Exception {
        private static final long serialVersionUID = 1L;

        enum Kind { CANNOT_DECRYPT, SEVERAL_FACES, RULE }

        final Kind kind;

        JanusException(Kind kind, String message) {
            super(message);
            this.kind = kind;
        }

        static JanusException cannotDecrypt() {
            return new JanusException(Kind.CANNOT_DECRYPT, "cannot decrypt");
        }

        static JanusException rule(String message) {
            return new JanusException(Kind.RULE, message);
        }
    }

    // ---- Sizes (spec 6) -------------------------------------------------------------

    static long blocks(long l) {
        return Math.max(1, (l + TB - 1) / TB);
    }

    static long encryptedSize(long l) {
        return l + 16 * blocks(l);
    }

    static long reserve(long l1) {
        return Math.max(R_MIN, (l1 + RHO - 1) / RHO);
    }

    static long padme(long l) {
        if (l < 2) {
            return l;
        }
        int e = 63 - Long.numberOfLeadingZeros(l);
        int s = 31 - Integer.numberOfLeadingZeros(e) + 1;
        long mask = (1L << (e - s)) - 1;
        return (l + mask) & ~mask;
    }

    /** Uniform integer in [a, b], by rejection. */
    static long uniform(SecureRandom rng, long a, long b) {
        long range = b - a;                        // b − a + 1 values
        if (range == 0) {
            return a;
        }
        int bits = 64 - Long.numberOfLeadingZeros(range);
        long mask = bits == 64 ? -1L : (1L << bits) - 1;
        while (true) {
            long x = rng.nextLong() & mask;
            if (Long.compareUnsigned(x, range) <= 0) {
                return a + x;
            }
        }
    }

    private static int[] permutation(SecureRandom rng, int n) {
        int[] p = new int[n];
        for (int i = 0; i < n; i++) {
            p[i] = i;
        }
        for (int i = n - 1; i > 0; i--) {
            int j = rng.nextInt(i + 1);
            int t = p[i];
            p[i] = p[j];
            p[j] = t;
        }
        return p;
    }

    // ---- Encryption (spec 7) ---------------------------------------------------------

    static void checkRules(Face main, List<Face> hidden) throws JanusException {
        if (hidden.size() > N_TAGS - 1) {
            throw JanusException.rule("at most " + (N_TAGS - 1) + " hidden faces");
        }
        List<Face> faces = new ArrayList<>();
        faces.add(main);
        faces.addAll(hidden);
        int total = 0;
        for (Face f : faces) {
            boolean hasPassword = f.password() != null;
            if (hasPassword == !f.publicKeys().isEmpty()) {
                throw JanusException.rule("a face has either one password or 1 to 16 public keys (R1)");
            }
            List<byte[]> keys = f.publicKeys();
            for (int a = 0; a < keys.size(); a++) {
                if (!XWing.checkPublicKey(keys.get(a))) {
                    throw JanusException.rule("invalid public key");
                }
                for (int b = a + 1; b < keys.size(); b++) {
                    if (Arrays.equals(keys.get(a), keys.get(b))) {
                        throw JanusException.rule("a public key is repeated within a face (R5)");
                    }
                }
            }
            total += f.recipients();
        }
        if (total > N_SLOTS) {
            throw JanusException.rule("at most " + N_SLOTS + " recipients over all faces (R3)");
        }
        long hiddenSize = 0;
        for (Face f : hidden) {
            hiddenSize += encryptedSize(f.plaintext().length);
        }
        if (hiddenSize > reserve(main.plaintext().length)) {
            throw JanusException.rule("the hidden faces do not fit in the reserve (R5)");
        }
        for (int a = 0; a < faces.size(); a++) {
            for (int b = a + 1; b < faces.size(); b++) {
                Face x = faces.get(a), y = faces.get(b);
                if (x.password() != null && y.password() != null
                        && MessageDigest.isEqual(x.password(), y.password())) {
                    throw JanusException.rule("two faces share a password (R5)");
                }
                for (byte[] kx : x.publicKeys()) {
                    for (byte[] ky : y.publicKeys()) {
                        if (Arrays.equals(kx, ky)) {
                            throw JanusException.rule("a public key appears in two faces (R5)");
                        }
                    }
                }
            }
        }
    }

    static byte[] encrypt(Face main, List<Face> hidden, SecureRandom rng) throws JanusException {
        checkRules(main, hidden);
        long l1 = main.plaintext().length;

        // 1. Sizes and positions.
        long ref = H + encryptedSize(l1) + reserve(l1);
        long fSize = uniform(rng, ref, padme(ref));
        if (fSize > Integer.MAX_VALUE - 16) {
            throw JanusException.rule("file too large for this client (2 GiB)");
        }
        long body = fSize - H;
        List<Face> faces = new ArrayList<>();
        faces.add(main);
        faces.addAll(hidden);
        long[] d = new long[faces.size()];
        int h = hidden.size();
        if (h > 0) {
            long free = body - encryptedSize(l1);
            for (Face f : hidden) {
                free -= encryptedSize(f.plaintext().length);
            }
            int[] order = permutation(rng, h);
            long[] b = new long[h];
            for (int m = 0; m < h; m++) {
                b[m] = uniform(rng, 0, free);
            }
            Arrays.sort(b);
            long placed = 0;
            for (int m = 0; m < h; m++) {
                int j = order[m] + 1;
                d[j] = encryptedSize(l1) + b[m] + placed;
                placed += encryptedSize(faces.get(j).plaintext().length);
            }
        }

        // 2. Random header and body.
        byte[] out = new byte[(int) fSize];
        rng.nextBytes(out);
        byte[] salt = Bytes.slice(out, SALT_OFF, SALT_OFF + 32);

        // 3-4. Slots.
        int[] pi = permutation(rng, N_SLOTS);
        int next = 0;
        byte[][] fileKeys = new byte[faces.size()][];
        for (int f = 0; f < faces.size(); f++) {
            Face face = faces.get(f);
            byte[] key = new byte[32];
            rng.nextBytes(key);
            fileKeys[f] = key;
            byte[] wrapPlain = Bytes.concat(key, Bytes.be64(d[f]), Bytes.be64(face.plaintext().length));
            if (face.password() != null) {
                int i = pi[next++];
                byte[] a = Argon2id.janus(face.password(), salt);
                byte[] k = Hkdf.derive(a, Bytes.concat(LABEL_WRAP_PASSWORD, new byte[] {(byte) i}));
                writeWrap(out, i, k, wrapPlain);
                Arrays.fill(a, (byte) 0);
                Arrays.fill(k, (byte) 0);
            }
            for (byte[] pk : face.publicKeys()) {
                int i = pi[next++];
                XWing.Hidden enc = XWing.encapsulateHidden(pk, rng);
                System.arraycopy(enc.slotPrefix(), 0, out, SLOTS_OFF + S * i, W_OFF);
                byte[] k = Hkdf.derive(enc.ss(), Bytes.concat(LABEL_WRAP_XWING, new byte[] {(byte) i}));
                writeWrap(out, i, k, wrapPlain);
                Arrays.fill(enc.ss(), (byte) 0);
                Arrays.fill(k, (byte) 0);
            }
            Arrays.fill(wrapPlain, (byte) 0);
        }

        // 5. Tags.
        int[] sigma = permutation(rng, N_TAGS);
        for (int f = 0; f < faces.size(); f++) {
            byte[] t = tag(fileKeys[f], fSize, d[f], faces.get(f).plaintext().length, out);
            System.arraycopy(t, 0, out, 32 * sigma[f], 32);
        }

        // 6. Body.
        for (int f = 0; f < faces.size(); f++) {
            encryptFace(fileKeys[f], faces.get(f).plaintext(), out, (int) (H + d[f]));
            Arrays.fill(fileKeys[f], (byte) 0);
        }
        return out;
    }

    private static void writeWrap(byte[] out, int slot, byte[] k, byte[] wrapPlain) {
        byte[] w = Aead.seal(k, ZERO_NONCE, wrapPlain);
        System.arraycopy(w, 0, out, SLOTS_OFF + S * slot + W_OFF, w.length);
    }

    private static byte[] tag(byte[] fileKey, long fSize, long d, long l, byte[] header) {
        byte[] tk = Hkdf.derive(fileKey, LABEL_HEADER);
        try {
            return Hkdf.hmac(tk, Bytes.be64(fSize), Bytes.be64(d), Bytes.be64(l),
                             Arrays.copyOfRange(header, SALT_OFF, H));
        } finally {
            Arrays.fill(tk, (byte) 0);
        }
    }

    private static byte[] blockNonce(long j, boolean last) {
        byte[] n = new byte[12];
        System.arraycopy(Bytes.be64(j), 0, n, 3, 8);
        n[11] = (byte) (last ? 1 : 0);
        return n;
    }

    /** STREAM encryption of a face (spec 7.1), written at {@code off}. */
    private static void encryptFace(byte[] fileKey, byte[] plain, byte[] out, int off) {
        byte[] kb = Hkdf.derive(fileKey, LABEL_BODY);
        long c = blocks(plain.length);
        int pos = off;
        for (long j = 0; j < c; j++) {
            int from = (int) (j * TB);
            int len = (int) Math.min(TB, plain.length - j * TB);
            byte[] ct = Aead.seal(kb, blockNonce(j, j == c - 1), plain, from, len);
            System.arraycopy(ct, 0, out, pos, ct.length);
            pos += ct.length;
        }
        Arrays.fill(kb, (byte) 0);
    }

    // ---- Decryption (spec 8) ---------------------------------------------------------

    static byte[] decryptWithPassword(byte[] file, byte[] password) throws JanusException {
        if (file.length < H) {
            throw JanusException.cannotDecrypt();
        }
        byte[] salt = Bytes.slice(file, SALT_OFF, SALT_OFF + 32);
        byte[] a = Argon2id.janus(password, salt);
        List<byte[]> keys = new ArrayList<>();
        for (int i = 0; i < N_SLOTS; i++) {
            keys.add(Hkdf.derive(a, Bytes.concat(LABEL_WRAP_PASSWORD, new byte[] {(byte) i})));
        }
        Arrays.fill(a, (byte) 0);
        return decrypt(file, keys, 1);
    }

    static byte[] decryptWithIdentities(byte[] file, List<XWing.KeyPair> identities) throws JanusException {
        if (file.length < H || identities.isEmpty()) {
            throw JanusException.cannotDecrypt();
        }
        List<byte[]> keys = new ArrayList<>();
        for (int i = 0; i < N_SLOTS; i++) {
            for (XWing.KeyPair id : identities) {
                byte[] ss = XWing.decapsulateHidden(id, file, SLOTS_OFF + S * i);
                keys.add(Hkdf.derive(ss, Bytes.concat(LABEL_WRAP_XWING, new byte[] {(byte) i})));
                Arrays.fill(ss, (byte) 0);
            }
        }
        return decrypt(file, keys, identities.size());
    }

    /**
     * Steps 2 to 7. {@code keys} holds the candidate wrapping keys, {@code perSlot} per slot,
     * in slot order. Every candidate gets the same work: AEAD open, HKDF, HMAC, 4 comparisons.
     */
    private static byte[] decrypt(byte[] file, List<byte[]> keys, int perSlot) throws JanusException {
        long fSize = file.length;
        byte[] authenticated = Arrays.copyOfRange(file, SALT_OFF, H);
        List<byte[]> valid = new ArrayList<>();
        for (int n = 0; n < keys.size(); n++) {
            int slot = n / perSlot;
            int wOff = SLOTS_OFF + S * slot + W_OFF;
            byte[] k = keys.get(n);
            byte[] plain = Aead.open(k, ZERO_NONCE, file, wOff, WRAP_PLAIN + Aead.TAG);
            Arrays.fill(k, (byte) 0);
            boolean opened = plain != null;
            if (!opened) {
                plain = new byte[WRAP_PLAIN];
            }
            byte[] fileKey = Bytes.slice(plain, 0, 32);
            byte[] tk = Hkdf.derive(fileKey, LABEL_HEADER);
            byte[] t = Hkdf.hmac(tk, Bytes.be64(fSize), Bytes.slice(plain, 32, 48), authenticated);
            boolean match = false;
            for (int x = 0; x < N_TAGS; x++) {
                match |= MessageDigest.isEqual(t, Arrays.copyOfRange(file, 32 * x, 32 * x + 32));
            }
            Arrays.fill(tk, (byte) 0);
            Arrays.fill(fileKey, (byte) 0);
            if (opened & match) {
                valid.add(plain);
            } else {
                Arrays.fill(plain, (byte) 0);
            }
        }

        // 4. Deduplicate on the full triple (K, d, l).
        List<byte[]> distinct = new ArrayList<>();
        for (byte[] v : valid) {
            boolean seen = false;
            for (byte[] w : distinct) {
                seen |= MessageDigest.isEqual(v, w);
            }
            if (!seen) {
                distinct.add(v);
            }
        }
        if (distinct.isEmpty()) {
            throw JanusException.cannotDecrypt();
        }
        if (distinct.size() > 1) {
            valid.forEach(v -> Arrays.fill(v, (byte) 0));
            throw new JanusException(JanusException.Kind.SEVERAL_FACES, "these credentials open several faces");
        }
        byte[] triple = distinct.get(0);
        byte[] fileKey = Bytes.slice(triple, 0, 32);
        long d = Bytes.readBe64(triple, 32);
        long l = Bytes.readBe64(triple, 40);
        valid.forEach(v -> Arrays.fill(v, (byte) 0));

        // 5. Bounds, without overflow: d and l are unsigned 64-bit.
        long body = fSize - H;
        if (d < 0 || l < 0 || d > body || l > body) {
            throw JanusException.cannotDecrypt();
        }
        long c = blocks(l);
        if (d + l + 16 * c > body) {
            throw JanusException.cannotDecrypt();
        }

        // 6. Body.
        byte[] kb = Hkdf.derive(fileKey, LABEL_BODY);
        Arrays.fill(fileKey, (byte) 0);
        byte[] out = new byte[(int) l];
        long pos = H + d;
        try {
            for (long j = 0; j < c; j++) {
                int len = (int) Math.min(TB, l - j * TB);
                byte[] p = Aead.open(kb, blockNonce(j, j == c - 1), file, (int) pos, len + Aead.TAG);
                if (p == null) {
                    Arrays.fill(out, (byte) 0);
                    throw JanusException.cannotDecrypt();
                }
                System.arraycopy(p, 0, out, (int) (j * TB), len);
                Arrays.fill(p, (byte) 0);
                pos += len + Aead.TAG;
            }
        } finally {
            Arrays.fill(kb, (byte) 0);
        }
        return out;
    }
}
