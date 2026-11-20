package org.janus;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * X-Wing key pairs and combiner (draft-connolly-cfrg-xwing-kem-11), and the hidden
 * encapsulation of Janus v1 (spec 5.2, 5.3): Elligator 2 for the X25519 part, masked
 * Kemeleon for the ML-KEM part.
 */
final class XWing {

    static final int PK_BYTES = MlKem768.EK_BYTES + 32;             // 1216
    private static final byte[] LABEL = Bytes.hex("5c2e2f2f5e5c"); // \.//^\
    private static final byte[] MASK_LABEL = Bytes.ascii("janus/v1/masque");

    private XWing() {
    }

    /** The key pair derived from a 32-byte seed (spec 3.1). */
    static final class KeyPair {
        final byte[] seed;
        final byte[] dkM;
        final byte[] ekM;
        final byte[] skX;
        final byte[] pkX;

        KeyPair(byte[] seed) {
            if (seed.length != 32) {
                throw new IllegalArgumentException("identity seed must be 32 bytes");
            }
            this.seed = seed.clone();
            byte[] expanded = Keccak.shake256(seed, 96);
            MlKem768.KeyPair m = MlKem768.keyGenInternal(Bytes.slice(expanded, 0, 32), Bytes.slice(expanded, 32, 64));
            this.ekM = m.ek();
            this.dkM = m.dk();
            this.skX = Bytes.slice(expanded, 64, 96);
            this.pkX = Curve25519.x25519(skX, Curve25519.U_9);
            Arrays.fill(expanded, (byte) 0);
        }

        byte[] publicKey() {
            return Bytes.concat(ekM, pkX);
        }

        void wipe() {
            Arrays.fill(seed, (byte) 0);
            Arrays.fill(dkM, (byte) 0);
            Arrays.fill(skX, (byte) 0);
        }
    }

    static byte[] combine(byte[] ssM, byte[] ssX, byte[] ctX, byte[] pkX) {
        return Bytes.sha3_256(Bytes.concat(ssM, ssX, ctX, pkX, LABEL));
    }

    /** Standard X-Wing deterministic encapsulation, for the draft's test vector: {ss, ct_M, ct_X}. */
    static byte[][] encapsulateDerand(byte[] pk, byte[] eseed) {
        byte[] ekM = Bytes.slice(pk, 0, MlKem768.EK_BYTES);
        byte[] pkX = Bytes.slice(pk, MlKem768.EK_BYTES, PK_BYTES);
        byte[] ekX = Bytes.slice(eseed, 32, 64);
        byte[] ctX = Curve25519.x25519(ekX, Curve25519.U_9);
        byte[] ssX = Curve25519.x25519(ekX, pkX);
        MlKem768.Encapsulation m = MlKem768.encapsInternal(ekM, Bytes.slice(eseed, 0, 32));
        return new byte[][] {combine(m.sharedKey(), ssX, ctX, pkX), m.ciphertext(), ctX};
    }

    /** Standard X-Wing decapsulation of ct = ct_M ‖ ct_X, for the draft's test vector. */
    static byte[] decapsulateStandard(KeyPair kp, byte[] ctM, byte[] ctX) {
        byte[] ssM = MlKem768.decaps(kp.dkM, ctM);
        byte[] ssX = Curve25519.x25519(kp.skX, ctX);
        return combine(ssM, ssX, ctX, kp.pkX);
    }

    /** The result of a hidden encapsulation: the first 1568 bytes of a slot, and ss. */
    record Hidden(byte[] slotPrefix, byte[] ss) {
    }

    /** Hidden X-Wing encapsulation (spec 5.2). {@code pk} must have passed {@link #checkPublicKey}. */
    static Hidden encapsulateHidden(byte[] pk, SecureRandom rng) {
        byte[] ekM = Bytes.slice(pk, 0, MlKem768.EK_BYTES);
        byte[] pkX = Bytes.slice(pk, MlKem768.EK_BYTES, PK_BYTES);
        byte[] s;
        byte[] ctX;
        byte[] r;
        while (true) {
            s = Curve25519.randomFullGroupScalar(rng);
            ctX = Curve25519.ladder(s, Curve25519.U_G);
            r = Elligator2.representative(ctX, rng);
            if (r != null) {
                break;
            }
            Arrays.fill(s, (byte) 0);
        }
        byte[] ssX = Curve25519.ladder(s, pkX);
        Arrays.fill(s, (byte) 0);
        MlKem768.Encapsulation m = MlKem768.encaps(ekM, rng);
        byte[] ss = combine(m.sharedKey(), ssX, ctX, pkX);
        byte[] kappa = Kemeleon.encode(m.ciphertext(), rng);
        byte[] mask = Keccak.shake256(Bytes.concat(MASK_LABEL, ssX, ctX), Kemeleon.ENCODED_BYTES);
        for (int i = 0; i < kappa.length; i++) {
            kappa[i] ^= mask[i];
        }
        Arrays.fill(ssX, (byte) 0);
        Arrays.fill(mask, (byte) 0);
        Arrays.fill(m.sharedKey(), (byte) 0);
        return new Hidden(Bytes.concat(r, kappa), ss);
    }

    /** Hidden X-Wing decapsulation (spec 5.3) of the slot at {@code slot[off..]}. Never fails. */
    static byte[] decapsulateHidden(KeyPair kp, byte[] slot, int off) {
        byte[] r = Arrays.copyOfRange(slot, off, off + 32);
        byte[] kappa = Arrays.copyOfRange(slot, off + 32, off + 32 + Kemeleon.ENCODED_BYTES);
        byte[] ctX = Elligator2.map(r);
        byte[] ssX = Curve25519.x25519(kp.skX, ctX);
        byte[] mask = Keccak.shake256(Bytes.concat(MASK_LABEL, ssX, ctX), Kemeleon.ENCODED_BYTES);
        for (int i = 0; i < kappa.length; i++) {
            kappa[i] ^= mask[i];
        }
        byte[] ctM = Kemeleon.decode(kappa);
        byte[] ssM = MlKem768.decaps(kp.dkM, ctM);
        byte[] ss = combine(ssM, ssX, ctX, kp.pkX);
        Arrays.fill(ssX, (byte) 0);
        Arrays.fill(ssM, (byte) 0);
        Arrays.fill(mask, (byte) 0);
        Arrays.fill(kappa, (byte) 0);
        return ss;
    }

    /**
     * Spec 3.1: length, the FIPS 203 encapsulation-key check on the ML-KEM part, and a canonical
     * pk_X (bit 255 clear, value below p). A canonical low-order pk_X is accepted, as in X-Wing.
     */
    static boolean checkPublicKey(byte[] pk) {
        if (pk.length != PK_BYTES) {
            return false;
        }
        byte[] pkX = Bytes.slice(pk, MlKem768.EK_BYTES, PK_BYTES);
        boolean canonical = (pkX[31] & 0x80) == 0 && Curve25519.fromLe(pkX).compareTo(Curve25519.P) < 0;
        return canonical && MlKem768.checkEncapsulationKey(Bytes.slice(pk, 0, MlKem768.EK_BYTES));
    }
}
