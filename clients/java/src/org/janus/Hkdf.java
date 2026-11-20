package org.janus;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HMAC-SHA-256 (JDK) and HKDF-SHA-256 (RFC 5869, written here). */
final class Hkdf {

    private static final int HASH_LEN = 32;

    private Hkdf() {
    }

    static byte[] hmac(byte[] key, byte[]... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] p : parts) {
                mac.update(p);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA-256 unavailable", e);
        }
    }

    static byte[] extract(byte[] salt, byte[] ikm) {
        return hmac(salt == null || salt.length == 0 ? new byte[HASH_LEN] : salt, ikm);
    }

    static byte[] expand(byte[] prk, byte[] info, int length) {
        if (length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("HKDF output too long");
        }
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int off = 0;
        for (int i = 1; off < length; i++) {
            t = hmac(prk, t, info, new byte[] {(byte) i});
            int n = Math.min(HASH_LEN, length - off);
            System.arraycopy(t, 0, out, off, n);
            off += n;
        }
        Arrays.fill(t, (byte) 0);
        return out;
    }

    static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length) {
        byte[] prk = extract(salt, ikm);
        try {
            return expand(prk, info, length);
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }

    /** The format's {@code HKDF(ikm, info)}: absent salt, 32-byte output (spec 2.1). */
    static byte[] derive(byte[] ikm, byte[] info) {
        return hkdf(null, ikm, info, 32);
    }
}
