package org.janus;

import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20-Poly1305 (RFC 8439) from the JDK, empty associated data.
 *
 * <p>A fresh {@link Cipher} is created for every call: the JDK refuses to encrypt twice
 * with the same key and nonce on one instance, and Janus wraps under a constant zero nonce
 * with fresh keys.
 */
final class Aead {

    static final int TAG = 16;

    private Aead() {
    }

    static byte[] seal(byte[] key, byte[] nonce, byte[] plaintext, int off, int len) {
        try {
            Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
            return c.doFinal(plaintext, off, len);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ChaCha20-Poly1305 unavailable", e);
        }
    }

    static byte[] seal(byte[] key, byte[] nonce, byte[] plaintext) {
        return seal(key, nonce, plaintext, 0, plaintext.length);
    }

    /** Returns the plaintext, or {@code null} if authentication fails. */
    static byte[] open(byte[] key, byte[] nonce, byte[] ciphertext, int off, int len) {
        try {
            Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
            return c.doFinal(ciphertext, off, len);
        } catch (AEADBadTagException e) {
            return null;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ChaCha20-Poly1305 unavailable", e);
        }
    }
}
