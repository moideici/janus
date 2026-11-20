package org.janus;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Text encoding of identities and public keys (spec 3.3), and identity files. */
final class Keys {

    static final String IDENTITY_HRP = "janus-secret-key-";
    static final String PUBLIC_HRP = "janus";
    private static final int BIP173_MAX = 90;

    private Keys() {
    }

    static String encodeIdentity(byte[] seed) {
        return Bech32m.encode(IDENTITY_HRP, Bech32m.toFiveBits(seed)).toUpperCase(Locale.ROOT);
    }

    static String encodePublicKey(byte[] pk) {
        return Bech32m.encode(PUBLIC_HRP, Bech32m.toFiveBits(pk));
    }

    /** The 32-byte seed of an identity string. */
    static byte[] decodeIdentity(String s) {
        Bech32m.Decoded d = Bech32m.decode(s.trim(), BIP173_MAX);
        if (d == null || !d.hrp().equals(IDENTITY_HRP)) {
            throw new IllegalArgumentException("not a Janus identity");
        }
        byte[] seed = Bech32m.fromFiveBits(d.data());
        if (seed == null || seed.length != 32) {
            throw new IllegalArgumentException("not a Janus identity");
        }
        return seed;
    }

    /** The 1216-byte public key of a public-key string, checked as spec 3.1 requires. */
    static byte[] decodePublicKey(String s) {
        Bech32m.Decoded d = Bech32m.decode(s.trim(), Integer.MAX_VALUE);
        if (d == null || !d.hrp().equals(PUBLIC_HRP)) {
            throw new IllegalArgumentException("not a Janus public key");
        }
        byte[] pk = Bech32m.fromFiveBits(d.data());
        if (pk == null || !XWing.checkPublicKey(pk)) {
            throw new IllegalArgumentException("not a valid Janus public key");
        }
        return pk;
    }

    /**
     * Reads an identity file (spec 3.3): comment lines start with '#'; the first line starting with
     * JANUS-SECRET-KEY-1 (any case) is the identity, and if it does not decode the file is invalid.
     * A byte-order mark is skipped (UTF-8, or UTF-16 as some Windows shells write), CRLF is
     * accepted and each line is trimmed.
     */
    static byte[] readIdentityFile(Path file) throws IOException {
        return parseIdentityFile(Files.readAllBytes(file), file.toString());
    }

    static byte[] parseIdentityFile(byte[] raw, String name) {
        String text;
        if (raw.length >= 2 && (raw[0] & 0xFF) == 0xFF && (raw[1] & 0xFF) == 0xFE) {
            text = new String(raw, 2, raw.length - 2, StandardCharsets.UTF_16LE);
        } else if (raw.length >= 2 && (raw[0] & 0xFF) == 0xFE && (raw[1] & 0xFF) == 0xFF) {
            text = new String(raw, 2, raw.length - 2, StandardCharsets.UTF_16BE);
        } else {
            text = new String(raw, StandardCharsets.UTF_8);
            if (!text.isEmpty() && text.charAt(0) == 0xFEFF) {
                text = text.substring(1);
            }
        }
        for (String line : text.split("\\r?\\n")) {
            String t = line.strip();
            if (t.startsWith("#")) {
                continue;
            }
            if (t.toUpperCase(Locale.ROOT).startsWith("JANUS-SECRET-KEY-1")) {
                return decodeIdentity(t);               // throws if invalid: no later line is tried
            }
        }
        throw new IllegalArgumentException("no Janus identity in " + name);
    }

    static String identityFileText(byte[] seed, byte[] pk) {
        return "# Janus identity (PROTOTYPE). Public key:\n# " + encodePublicKey(pk) + "\n"
                + encodeIdentity(seed) + "\n";
    }

    /** Reads public keys, one per line; blank lines and '#' comments are ignored. */
    static List<byte[]> readPublicKeyFile(Path file) throws IOException {
        List<byte[]> keys = new ArrayList<>();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            String t = line.strip();
            if (!t.isEmpty() && !t.startsWith("#")) {
                keys.add(decodePublicKey(t));
            }
        }
        return keys;
    }
}
