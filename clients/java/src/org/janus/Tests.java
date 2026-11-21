package org.janus;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Self-test: primitive known answers, X-Wing, Bech32m, the reference test vectors, round
 * trips and interoperability with the reference binary. No test framework: run with
 * {@code java -cp out/janus.jar org.janus.Tests [REPOSITORY_ROOT]} or {@code janus selftest}.
 */
public final class Tests {

    private final Path root;
    private final SecureRandom rng = new SecureRandom();
    private int passed;
    private int failed;

    private Tests(Path root) {
        this.root = root;
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        Path root = args.length > 0 ? Path.of(args[0]) : findRoot();
        if (root == null || !Files.isDirectory(root.resolve("janus-rs/vecteurs"))) {
            System.err.println("cannot find the repository root (with janus-rs/vecteurs); pass it as an argument");
            return 2;
        }
        Tests t = new Tests(root.toAbsolutePath().normalize());
        long start = System.nanoTime();
        t.section("1. primitives (known answers)", t::primitives);
        t.section("2. X-Wing draft-11 vector 1, hidden encapsulation", t::xwing);
        t.section("3. Bech32m (BIP 350)", t::bech32m);
        t.section("4. cles.json", t::keyVectors);
        t.section("5. reference test vectors", t::fileVectors);
        t.section("6. round trips and rules", t::roundTrips);
        t.section("7. interoperability with the reference binary", t::interop);
        t.section("8. command line", t::commandLine);
        System.out.printf("%n%d passed, %d failed (%.1f s)%n", t.passed, t.failed, seconds(start));
        return t.failed == 0 ? 0 : 1;
    }

    private static Path findRoot() {
        for (Path p = Path.of("").toAbsolutePath(); p != null; p = p.getParent()) {
            if (Files.exists(p.resolve("spec/janus-v1.md")) && Files.isDirectory(p.resolve("janus-rs/vecteurs"))) {
                return p;
            }
        }
        return null;
    }

    private interface Body {
        void run() throws Exception;
    }

    private void section(String name, Body body) {
        System.out.println("\n== " + name);
        long start = System.nanoTime();
        try {
            body.run();
        } catch (Exception | AssertionError e) {
            fail("section aborted: " + e);
            e.printStackTrace(System.out);
        }
        System.out.printf("   (%.2f s)%n", seconds(start));
    }

    private static double seconds(long start) {
        return (System.nanoTime() - start) / 1e9;
    }

    private void check(String name, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("   ok    " + name);
        } else {
            fail(name);
        }
    }

    private void fail(String name) {
        failed++;
        System.out.println("   FAIL  " + name);
    }

    private void checkHex(String name, byte[] actual, String expectedHex) {
        boolean ok = Bytes.hex(actual).equals(expectedHex);
        check(name, ok);
        if (!ok) {
            System.out.println("         got      " + Bytes.hex(actual));
            System.out.println("         expected " + expectedHex);
        }
    }

    // ---- 1. Primitives --------------------------------------------------------------------

    private void primitives() {
        byte[] abc = Bytes.ascii("abc");
        byte[] empty = new byte[0];
        checkHex("SHAKE128(\"\", 32)", Keccak.shake128(empty, 32),
                 "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        checkHex("SHAKE256(\"\", 64)", Keccak.shake256(empty, 64),
                 "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
                 + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
        checkHex("SHAKE128(\"abc\", 32)", Keccak.shake128(abc, 32),
                 "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
        checkHex("SHAKE256(\"abc\", 32)", Keccak.shake256(abc, 32),
                 "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
        checkHex("SHA3-256(\"abc\") (own sponge)", Keccak.sha3_256(abc),
                 "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        checkHex("SHA3-512(\"abc\") (own sponge)", Keccak.sha3_512(abc),
                 "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                 + "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
        boolean same = true;
        for (int n = 0; n <= 420; n += 7) {
            byte[] m = new byte[n];
            rng.nextBytes(m);
            same &= Arrays.equals(Keccak.sha3_256(m), Bytes.sha3_256(m));
            same &= Arrays.equals(Keccak.sha3_512(m), Bytes.sha3_512(m));
        }
        check("own Keccak agrees with the JDK's SHA3-256/512 on 61 lengths (0..420 bytes)", same);
        // Squeezing in pieces gives the same stream as squeezing at once.
        Keccak x = Keccak.shake128().absorb(abc);
        byte[] parts = Bytes.concat(x.squeeze(100), x.squeeze(300));
        check("SHAKE128 incremental squeeze", Arrays.equals(parts, Keccak.shake128(abc, 400)));

        checkHex("HKDF-SHA-256, RFC 5869 test case 1",
                 Hkdf.hkdf(Bytes.hex("000102030405060708090a0b0c"),
                           Bytes.hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                           Bytes.hex("f0f1f2f3f4f5f6f7f8f9"), 42),
                 "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
        checkHex("BLAKE2b-512(\"abc\"), RFC 7693", Blake2b.hash(abc, 64),
                 "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                 + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
        byte[] pw = new byte[32];
        Arrays.fill(pw, (byte) 1);
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 2);
        byte[] secret = new byte[8];
        Arrays.fill(secret, (byte) 3);
        byte[] ad = new byte[12];
        Arrays.fill(ad, (byte) 4);
        checkHex("Argon2id, RFC 9106 section 5.3", Argon2id.hash(pw, salt, secret, ad, 32, 3, 4, 32),
                 "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
        long t0 = System.nanoTime();
        Argon2id.janus(Bytes.ascii("janus"), new byte[32]);
        System.out.printf("   info  one Argon2id with the Janus parameters (64 MiB, t=3, p=4): %.2f s%n", seconds(t0));
    }

    // ---- 2. X-Wing ---------------------------------------------------------------------------

    private void xwing() {
        byte[] seed = Bytes.hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        byte[] eseed = Bytes.hex("3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"
                                 + "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2");
        String expected = "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384";
        XWing.KeyPair kp = new XWing.KeyPair(seed);
        byte[][] enc = XWing.encapsulateDerand(kp.publicKey(), eseed);
        checkHex("X-Wing vector 1: encapsulation shared secret", enc[0], expected);
        checkHex("X-Wing vector 1: decapsulation shared secret", XWing.decapsulateStandard(kp, enc[1], enc[2]), expected);
        byte[] badCt = enc[1].clone();
        badCt[5] ^= 1;
        check("ML-KEM implicit rejection gives another secret",
              !Bytes.hex(XWing.decapsulateStandard(kp, badCt, enc[2])).equals(expected));
        checkHex("X25519, RFC 7748 section 5.2 vector 1",
                 Curve25519.x25519(Bytes.hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                                   Bytes.hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
                 "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        // Elligator 2: representatives map back; Kemeleon decodes what it encodes.
        boolean ellOk = true;
        int found = 0;
        for (int n = 0; n < 40; n++) {
            byte[] s = Curve25519.randomFullGroupScalar(rng);
            byte[] u = Curve25519.ladder(s, Curve25519.U_G);
            byte[] r = Elligator2.representative(u, rng);
            if (r != null) {
                found++;
                ellOk &= Arrays.equals(Elligator2.map(r), u);
            }
        }
        check("Elligator 2: " + found + "/40 random points have a representative, all map back", ellOk && found > 5);
        boolean unclamped = true;
        for (int n = 0; n < 8; n++) {
            byte[] s = Curve25519.randomFullGroupScalar(rng);
            byte[] ctX = Curve25519.ladder(s, Curve25519.U_G);
            unclamped &= Arrays.equals(Curve25519.ladder(s, kp.pkX), Curve25519.x25519(kp.skX, ctX));
        }
        check("unclamped ladder over the full group agrees with X25519 of the recipient", unclamped);
        byte[] m = new byte[32];
        rng.nextBytes(m);
        byte[] ct = MlKem768.encapsInternal(kp.ekM, m).ciphertext();
        check("Kemeleon: DecodeCtxt(EncodeCtxt(ct)) = ct", Arrays.equals(Kemeleon.decode(Kemeleon.encode(ct, rng)), ct));
        XWing.Hidden h = XWing.encapsulateHidden(kp.publicKey(), rng);
        byte[] slot = Bytes.concat(h.slotPrefix(), new byte[64]);
        check("hidden X-Wing: decapsulation finds the same ss", Arrays.equals(XWing.decapsulateHidden(kp, slot, 0), h.ss()));
        byte[] pk = kp.publicKey();
        check("public-key check accepts a valid key", XWing.checkPublicKey(pk));
        byte[] bad = pk.clone();
        bad[0] = (byte) 0xFF;
        bad[1] |= 0x0F;                       // first coefficient = 4095 >= q
        check("public-key check rejects a coefficient >= q", !XWing.checkPublicKey(bad));
        check("public-key check rejects pk_X with bit 255 set", !XWing.checkPublicKey(withPkX(pk, setBit255(kp.pkX))));
        check("public-key check rejects pk_X = p", !XWing.checkPublicKey(withPkX(pk, Curve25519.toLe(Curve25519.P))));
        check("public-key check rejects pk_X = 2^255 - 1",
              !XWing.checkPublicKey(withPkX(pk, Curve25519.toLe(Curve25519.P.add(java.math.BigInteger.valueOf(18))))));
        check("public-key check accepts pk_X = p - 1 (canonical)",
              XWing.checkPublicKey(withPkX(pk, Curve25519.toLe(Curve25519.P.subtract(java.math.BigInteger.ONE)))));
        check("public-key string with a non-canonical pk_X rejected",
              rejects(() -> Keys.decodePublicKey(Keys.encodePublicKey(withPkX(pk, setBit255(kp.pkX))))));
        boolean lowOrder = true;
        for (String u : new String[] {"00", "01", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"}) {
            byte[] lo = withPkX(pk, Arrays.copyOf(Bytes.hex(u), 32));
            lowOrder &= XWing.checkPublicKey(lo) && Keys.decodePublicKey(Keys.encodePublicKey(lo)) != null;
            try {
                Janus.encrypt(Janus.Face.withKeys(new byte[10], List.of(lo)), List.of(), rng);
            } catch (Janus.JanusException e) {
                lowOrder = false;
            }
        }
        check("canonical low-order pk_X (0, 1, order 8) accepted, and encryption to it works", lowOrder);
    }

    // ---- 3. Bech32m --------------------------------------------------------------------------

    private void bech32m() {
        String[] valid = {"A1LQFN3A", "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v", "?1v759aa"};
        for (String v : valid) {
            check("valid   " + v, Bech32m.decode(v, 90) != null);
        }
        String[] invalid = {"a12uel5l", "A1lqfn3a", " 1xj0phk", "\u007f1g6xzxy", "\u00801vctc34",
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
            "qyrz8wqd2c9m", "1qyrz8wqd2c9m", "y1b0jsk6g", "lt1igcx5c0", "in1muywd", "mm1crxm3i",
            "au1s5cgom", "M1VUXWEZ", "16plkw9", "1p2gdwpf"};
        for (String v : invalid) {
            check("invalid " + v.replaceAll("[^\\x21-\\x7e]", "?"), Bech32m.decode(v, 90) == null);
        }
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 1);
        String id = Keys.encodeIdentity(seed);
        check("identity is 76 characters", id.length() == 76);
        check("identity decodes in lower case too", Arrays.equals(Keys.decodeIdentity(id.toLowerCase()), seed));
        String pk = Keys.encodePublicKey(new XWing.KeyPair(seed).publicKey());
        check("public key is 1958 characters", pk.length() == 1958);
        check("a public key is not accepted as an identity", rejects(() -> Keys.decodeIdentity(pk)));
        check("an identity is not accepted as a public key", rejects(() -> Keys.decodePublicKey(id)));
        check("mixed case rejected", rejects(() -> Keys.decodeIdentity(id.substring(0, 20) + id.substring(20).toLowerCase())));
        String flipped = id.substring(0, 40) + (id.charAt(40) == 'Q' ? 'P' : 'Q') + id.substring(41);
        check("wrong checksum rejected", rejects(() -> Keys.decodeIdentity(flipped)));
        String wrongHrp = Bech32m.encode("janus-secret-kez-", Bech32m.toFiveBits(seed)).toUpperCase();
        check("wrong human-readable part rejected", rejects(() -> Keys.decodeIdentity(wrongHrp)));
        String shortData = Bech32m.encode(Keys.IDENTITY_HRP, Bech32m.toFiveBits(new byte[31])).toUpperCase();
        check("wrong data length rejected", rejects(() -> Keys.decodeIdentity(shortData)));
        byte[] five = Bech32m.toFiveBits(seed);
        five[five.length - 1] |= 1;           // 256 bits in 52 groups: 4 padding bits, set one
        String badPad = Bech32m.encode(Keys.IDENTITY_HRP, five).toUpperCase();
        check("non-zero padding rejected", rejects(() -> Keys.decodeIdentity(badPad)));
        String longPad = Bech32m.encode(Keys.IDENTITY_HRP, Arrays.copyOf(Bech32m.toFiveBits(seed), 53)).toUpperCase();
        check("over-long padding rejected", rejects(() -> Keys.decodeIdentity(longPad)));
        identityFiles();
    }

    private static byte[] withPkX(byte[] pk, byte[] pkX) {
        byte[] out = pk.clone();
        System.arraycopy(pkX, 0, out, MlKem768.EK_BYTES, 32);
        return out;
    }

    private static byte[] setBit255(byte[] x) {
        byte[] out = x.clone();
        out[31] |= (byte) 0x80;
        return out;
    }

    private void identityFiles() {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 7);
        String id = Keys.encodeIdentity(seed);
        byte[] other = new byte[32];
        Arrays.fill(other, (byte) 8);
        byte[] crlf = ("\uFEFF# comment\r\n\r\n   " + id.toLowerCase() + "  \r\n").getBytes(StandardCharsets.UTF_8);
        check("identity file: UTF-8 BOM, CRLF, whitespace, lower case",
              Arrays.equals(Keys.parseIdentityFile(crlf, "t"), seed));
        byte[] utf16 = Bytes.concat(new byte[] {(byte) 0xFF, (byte) 0xFE},
                                    ("# c\r\n" + id + "\r\n").getBytes(StandardCharsets.UTF_16LE));
        check("identity file: UTF-16LE with BOM", Arrays.equals(Keys.parseIdentityFile(utf16, "t"), seed));
        String broken = id.substring(0, 30) + (id.charAt(30) == 'Q' ? 'P' : 'Q') + id.substring(31);
        byte[] twoLines = ("# c\n" + broken + "\n" + Keys.encodeIdentity(other) + "\n").getBytes(StandardCharsets.UTF_8);
        check("identity file: an invalid first identity line makes the file invalid (no later line tried)",
              rejects(() -> Keys.parseIdentityFile(twoLines, "t")));
        byte[] first = (id + "\n" + Keys.encodeIdentity(other) + "\n").getBytes(StandardCharsets.UTF_8);
        check("identity file: the first identity line is used", Arrays.equals(Keys.parseIdentityFile(first, "t"), seed));
        check("identity file: no identity line rejected",
              rejects(() -> Keys.parseIdentityFile("# nothing\n".getBytes(StandardCharsets.UTF_8), "t")));
    }

    private static boolean rejects(Runnable r) {
        try {
            r.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    // ---- 4. cles.json ------------------------------------------------------------------------

    private void keyVectors() throws IOException {
        Map<String, Object> doc = Json.obj(Json.parse(Files.readString(root.resolve("janus-rs/vecteurs/cles.json"))));
        for (Object o : Json.list(doc.get("cles"))) {
            Map<String, Object> k = Json.obj(o);
            byte[] seed = Bytes.hex((String) k.get("graine"));
            XWing.KeyPair kp = new XWing.KeyPair(seed);
            String tag = ((String) k.get("graine")).substring(0, 8) + "…";
            check(tag + " identity string", Keys.encodeIdentity(seed).equals(k.get("identite")));
            check(tag + " public-key string", Keys.encodePublicKey(kp.publicKey()).equals(k.get("cle_publique")));
            check(tag + " SHA-256 of the public key",
                  Bytes.hex(Bytes.sha256(kp.publicKey())).equals(k.get("cle_publique_hex_sha256")));
            check(tag + " identity decodes to the seed", Arrays.equals(Keys.decodeIdentity((String) k.get("identite")), seed));
            check(tag + " public key decodes", Arrays.equals(Keys.decodePublicKey((String) k.get("cle_publique")), kp.publicKey()));
        }
    }

    // ---- 5. Test vectors ---------------------------------------------------------------------

    private void fileVectors() throws IOException {
        Path dir = root.resolve("janus-rs/vecteurs");
        Map<String, Object> doc = Json.obj(Json.parse(Files.readString(dir.resolve("manifeste.json"))));
        byte[] foreignSeed = new byte[32];
        Arrays.fill(foreignSeed, (byte) 0xEE);
        XWing.KeyPair foreign = new XWing.KeyPair(foreignSeed);
        long start = System.nanoTime();
        for (Object o : Json.list(doc.get("vecteurs"))) {
            Map<String, Object> v = Json.obj(o);
            String name = (String) v.get("fichier");
            byte[] file = Files.readAllBytes(dir.resolve(name));
            check(name + ": size and SHA-256", file.length == (Long) v.get("taille")
                  && Bytes.hex(Bytes.sha256(file)).equals(v.get("sha256_fichier")));
            String expectedMain = (String) v.get("sha256_clair");
            long mainLength = (Long) v.get("clair_longueur");
            check(name + ": manifest plaintext rule", Bytes.hex(Bytes.sha256(mainPlaintext((int) mainLength))).equals(expectedMain));
            Map<String, Object> opening = Json.obj(v.get("ouverture"));
            if (opening.get("type").equals("mot_de_passe")) {
                byte[] pw = ((String) opening.get("valeur")).getBytes(StandardCharsets.UTF_8);
                checkOpens(name + ": main face, password", () -> Janus.decryptWithPassword(file, pw), expectedMain, mainLength);
            } else {
                for (Object s : Json.list(opening.get("chacune_ouvre"))) {
                    XWing.KeyPair kp = new XWing.KeyPair(Bytes.hex((String) s));
                    checkOpens(name + ": identity " + ((String) s).substring(0, 4) + "…",
                               () -> Janus.decryptWithIdentities(file, List.of(kp)), expectedMain, mainLength);
                }
            }
            int j = 0;
            for (Object hObj : Json.list(opening.get("visages_caches"))) {
                Map<String, Object> hf = Json.obj(hObj);
                byte[] pw = ((String) hf.get("mot_de_passe")).getBytes(StandardCharsets.UTF_8);
                long len = (Long) hf.get("clair_longueur");
                String sha = (String) hf.get("sha256_clair");
                check(name + ": hidden plaintext rule " + j, Bytes.hex(Bytes.sha256(hiddenPlaintext((int) len, j))).equals(sha));
                checkOpens(name + ": hidden face " + j + " (\"" + hf.get("mot_de_passe") + "\")",
                           () -> Janus.decryptWithPassword(file, pw), sha, len);
                j++;
            }
            checkFails(name + ": foreign identity (0xEE…) fails", () -> Janus.decryptWithIdentities(file, List.of(foreign)));
            if (opening.get("type").equals("mot_de_passe")) {
                checkFails(name + ": wrong password fails", () -> Janus.decryptWithPassword(file, Bytes.ascii("Janus")));
            }
            byte[] truncated = Arrays.copyOf(file, file.length - 1);
            if (opening.get("type").equals("mot_de_passe")) {
                byte[] pw = ((String) opening.get("valeur")).getBytes(StandardCharsets.UTF_8);
                checkFails(name + ": truncated by one byte fails", () -> Janus.decryptWithPassword(truncated, pw));
            } else {
                XWing.KeyPair first = new XWing.KeyPair(Bytes.hex((String) Json.list(opening.get("chacune_ouvre")).get(0)));
                checkFails(name + ": truncated by one byte fails", () -> Janus.decryptWithIdentities(truncated, List.of(first)));
            }
        }
        System.out.printf("   info  all vectors: %.2f s%n", seconds(start));
    }

    private interface Decryption {
        byte[] run() throws Janus.JanusException;
    }

    private void checkOpens(String name, Decryption d, String sha, long length) {
        try {
            byte[] p = d.run();
            check(name, p.length == length && Bytes.hex(Bytes.sha256(p)).equals(sha));
        } catch (Janus.JanusException e) {
            fail(name + " (" + e.getMessage() + ")");
        }
    }

    private void checkOpens(String name, Decryption d, byte[] expected) {
        checkOpens(name, d, Bytes.hex(Bytes.sha256(expected)), expected.length);
    }

    private void checkFails(String name, Decryption d) {
        checkFails(name, d, Janus.JanusException.Kind.CANNOT_DECRYPT);
    }

    private void checkFails(String name, Decryption d, Janus.JanusException.Kind kind) {
        try {
            d.run();
            fail(name + " (it opened)");
        } catch (Janus.JanusException e) {
            check(name, e.kind == kind);
        }
    }

    static byte[] mainPlaintext(int n) {
        byte[] p = new byte[n];
        for (int k = 0; k < n; k++) {
            p[k] = (byte) (31 * k + 7);
        }
        return p;
    }

    static byte[] hiddenPlaintext(int n, int j) {
        byte[] p = new byte[n];
        for (int k = 0; k < n; k++) {
            p[k] = (byte) (17 * k + 3 + 50 * j);
        }
        return p;
    }

    // ---- 6. Round trips -----------------------------------------------------------------------

    private byte[] random(int n) {
        byte[] b = new byte[n];
        rng.nextBytes(b);
        return b;
    }

    private XWing.KeyPair newIdentity() {
        return new XWing.KeyPair(random(32));
    }

    private void roundTrips() throws Janus.JanusException {
        byte[] p = random(1000);
        byte[] pw = Bytes.ascii("correct horse");
        byte[] f = Janus.encrypt(Janus.Face.withPassword(p, pw), List.of(), rng);
        check("file size within the PADME bucket of Ref", sizeOk(f.length, p.length));
        checkOpens("password", () -> Janus.decryptWithPassword(f, pw), p);
        checkFails("password: wrong password fails", () -> Janus.decryptWithPassword(f, Bytes.ascii("correct horsf")));

        XWing.KeyPair a = newIdentity();
        byte[] f1 = Janus.encrypt(Janus.Face.withKeys(p, List.of(a.publicKey())), List.of(), rng);
        checkOpens("one key", () -> Janus.decryptWithIdentities(f1, List.of(a)), p);
        checkFails("one key: other identity fails", () -> Janus.decryptWithIdentities(f1, List.of(newIdentity())));
        checkOpens("one key: opened among several identities",
                   () -> Janus.decryptWithIdentities(f1, List.of(newIdentity(), a)), p);
        byte[] tampered = f1.clone();
        tampered[Janus.H + 3] ^= 1;
        checkFails("one key: modified body fails", () -> Janus.decryptWithIdentities(tampered, List.of(a)));
        byte[] tamperedHeader = f1.clone();
        tamperedHeader[200] ^= 1;
        checkFails("one key: modified header fails", () -> Janus.decryptWithIdentities(tamperedHeader, List.of(a)));

        List<XWing.KeyPair> ids = new ArrayList<>();
        List<byte[]> pks = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            ids.add(newIdentity());
            pks.add(ids.get(i).publicKey());
        }
        byte[] f16 = Janus.encrypt(Janus.Face.withKeys(p, pks), List.of(), rng);
        boolean all = true;
        for (XWing.KeyPair id : ids) {
            try {
                all &= Arrays.equals(Janus.decryptWithIdentities(f16, List.of(id)), p);
            } catch (Janus.JanusException e) {
                all = false;
            }
        }
        check("16 keys: each of the 16 identities opens", all);

        byte[] decoy = random(5000);
        byte[] secret = random(3000);
        byte[] f2 = Janus.encrypt(Janus.Face.withPassword(decoy, Bytes.ascii("decoy")),
                                  List.of(Janus.Face.withPassword(secret, Bytes.ascii("secret"))), rng);
        check("decoy + 1 hidden: size depends on the decoy only", sizeOk(f2.length, decoy.length));
        checkOpens("decoy + 1 hidden: decoy", () -> Janus.decryptWithPassword(f2, Bytes.ascii("decoy")), decoy);
        checkOpens("decoy + 1 hidden: hidden face", () -> Janus.decryptWithPassword(f2, Bytes.ascii("secret")), secret);

        XWing.KeyPair b = newIdentity(), c = newIdentity(), e = newIdentity();
        byte[] h1 = random(20000), h2 = random(0), h3 = random(40000);
        byte[] f3 = Janus.encrypt(Janus.Face.withPassword(decoy, Bytes.ascii("m")), List.of(
                Janus.Face.withKeys(h1, List.of(b.publicKey())),
                Janus.Face.withPassword(h2, Bytes.ascii("h2")),
                Janus.Face.withKeys(h3, List.of(c.publicKey(), e.publicKey()))), rng);
        checkOpens("decoy + 3 hidden: decoy (password)", () -> Janus.decryptWithPassword(f3, Bytes.ascii("m")), decoy);
        checkOpens("decoy + 3 hidden: hidden 1 (key)", () -> Janus.decryptWithIdentities(f3, List.of(b)), h1);
        checkOpens("decoy + 3 hidden: hidden 2 (password, empty)", () -> Janus.decryptWithPassword(f3, Bytes.ascii("h2")), h2);
        checkOpens("decoy + 3 hidden: hidden 3 (second of two keys)", () -> Janus.decryptWithIdentities(f3, List.of(e)), h3);
        checkFails("decoy + 3 hidden: identities of two faces -> several faces",
                   () -> Janus.decryptWithIdentities(f3, List.of(b, c)), Janus.JanusException.Kind.SEVERAL_FACES);
        checkOpens("decoy + 3 hidden: two identities of the same face open it",
                   () -> Janus.decryptWithIdentities(f3, List.of(c, e)), h3);

        for (int n : new int[] {0, 65536, 65537}) {
            byte[] q = random(n);
            byte[] fq = Janus.encrypt(Janus.Face.withKeys(q, List.of(a.publicKey())), List.of(), rng);
            checkOpens(n + "-byte plaintext", () -> Janus.decryptWithIdentities(fq, List.of(a)), q);
            check(n + "-byte plaintext: file size", sizeOk(fq.length, n));
        }
        byte[] big = random(3 * 65536 + 5);
        byte[] fb = Janus.encrypt(Janus.Face.withKeys(big, List.of(a.publicKey())),
                                  List.of(Janus.Face.withKeys(random(1000), List.of(b.publicKey()))), rng);
        checkOpens("4-block decoy with a hidden face", () -> Janus.decryptWithIdentities(fb, List.of(a)), big);

        // Rules.
        List<byte[]> seventeen = new ArrayList<>(pks);
        seventeen.add(a.publicKey());
        checkRule("17 recipients refused (R3)", Janus.Face.withKeys(p, seventeen), List.of());
        checkRule("17 recipients over two faces refused (R3)", Janus.Face.withKeys(p, pks),
                  List.of(Janus.Face.withPassword(p, Bytes.ascii("x"))));
        checkRule("same password in two faces refused (R5)", Janus.Face.withPassword(p, Bytes.ascii("same")),
                  List.of(Janus.Face.withPassword(p, Bytes.ascii("same"))));
        checkRule("same public key in two faces refused (R5)", Janus.Face.withKeys(p, List.of(a.publicKey())),
                  List.of(Janus.Face.withKeys(p, List.of(a.publicKey()))));
        checkRule("hidden faces larger than the reserve refused (R5)", Janus.Face.withPassword(p, Bytes.ascii("a")),
                  List.of(Janus.Face.withPassword(random(40000), Bytes.ascii("b")),
                          Janus.Face.withPassword(random(30000), Bytes.ascii("c"))));
        checkRule("4 hidden faces refused", Janus.Face.withPassword(p, Bytes.ascii("a")), List.of(
                Janus.Face.withPassword(p, Bytes.ascii("b")), Janus.Face.withPassword(p, Bytes.ascii("c")),
                Janus.Face.withPassword(p, Bytes.ascii("d")), Janus.Face.withPassword(p, Bytes.ascii("e"))));
        checkRule("public key repeated within one face refused (R5)",
                  Janus.Face.withKeys(p, List.of(a.publicKey(), b.publicKey(), a.publicKey())), List.of());
        checkRule("password and key in one face refused (R1)",
                  new Janus.Face(p, Bytes.ascii("a"), List.of(a.publicKey())), List.of());
        byte[] reserveFit = random((int) (Janus.reserve(p.length) - 16));
        try {
            Janus.checkRules(Janus.Face.withPassword(p, Bytes.ascii("a")),
                             List.of(Janus.Face.withPassword(reserveFit, Bytes.ascii("b"))));
            check("a hidden face filling the reserve exactly is accepted", true);
        } catch (Janus.JanusException ex) {
            fail("a hidden face filling the reserve exactly is accepted (" + ex.getMessage() + ")");
        }
    }

    private static boolean sizeOk(long f, long l1) {
        long ref = Janus.H + Janus.encryptedSize(l1) + Janus.reserve(l1);
        long bucket = Janus.padme(ref); // spec § 6.2: F lies in the PADME bucket of Ref
        return f >= bucket && f <= bucket + Janus.bucketMask(bucket);
    }

    private void checkRule(String name, Janus.Face main, List<Janus.Face> hidden) {
        try {
            Janus.checkRules(main, hidden);
            fail(name + " (accepted)");
        } catch (Janus.JanusException e) {
            check(name, e.kind == Janus.JanusException.Kind.RULE);
        }
    }

    // ---- 7. Interoperability -------------------------------------------------------------------

    private record Result(int code, String out, String err) {
    }

    private Result rust(Path exe, Path cwd, Map<String, String> env, String... args) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        cmd.add(exe.toString());
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(cwd.toFile());
        pb.environment().keySet().removeIf(k -> k.startsWith("JANUS_MDP"));
        pb.environment().putAll(env);
        pb.redirectInput(ProcessBuilder.Redirect.from(new java.io.File(System.getProperty("os.name").startsWith("Windows") ? "NUL" : "/dev/null")));
        Process pr = pb.start();
        byte[] out = pr.getInputStream().readAllBytes();
        byte[] err = pr.getErrorStream().readAllBytes();
        int code = pr.waitFor();
        return new Result(code, new String(out, StandardCharsets.UTF_8), new String(err, StandardCharsets.UTF_8));
    }

    private void interop() throws Exception {
        Path exe = root.resolve("janus-rs/target/release/janus.exe");
        if (!Files.exists(exe)) {
            exe = root.resolve("janus-rs/target/release/janus");
        }
        if (!Files.exists(exe)) {
            System.out.println("   SKIP  reference binary not found (janus-rs/target/release/janus[.exe]); build it with cargo");
            return;
        }
        Path tmp = Files.createTempDirectory("janus-java-interop");
        try {
            interopIn(exe, tmp);
        } finally {
            try (Stream<Path> s = Files.walk(tmp)) {
                s.sorted(Comparator.reverseOrder()).forEach(q -> q.toFile().delete());
            }
        }
    }

    private void interopIn(Path exe, Path tmp) throws Exception {
        // Identities: one from the reference tool, one from this client.
        Result r = rust(exe, tmp, Map.of(), "cles", "rust.id");
        check("reference creates an identity", r.code() == 0);
        String rustPub = r.out().strip();
        byte[] rustSeed = Keys.readIdentityFile(tmp.resolve("rust.id"));
        XWing.KeyPair rustKp = new XWing.KeyPair(rustSeed);
        check("reference identity file read here; same public key", Keys.encodePublicKey(rustKp.publicKey()).equals(rustPub));

        XWing.KeyPair javaKp = newIdentity();
        Files.writeString(tmp.resolve("java.id"), Keys.identityFileText(javaKp.seed, javaKp.publicKey()));
        String javaPub = Keys.encodePublicKey(javaKp.publicKey());
        r = rust(exe, tmp, Map.of(), "publique", "java.id");
        check("this client's identity file read by the reference; same public key", r.code() == 0 && r.out().strip().equals(javaPub));

        // Java encrypts, reference decrypts.
        byte[] p1 = random(70000);
        Files.write(tmp.resolve("j-pw.janus"), Janus.encrypt(Janus.Face.withPassword(p1, "mot de passe é".getBytes(StandardCharsets.UTF_8)), List.of(), rng));
        rustOpens("Java password file opens with the reference", exe, tmp, "j-pw.janus", p1,
                  Map.of("JANUS_MDP", "mot de passe é"), "-m");
        rustFails("Java password file: wrong password fails with the reference", exe, tmp, "j-pw.janus",
                  Map.of("JANUS_MDP", "mot de passe e"), "-m");

        byte[] p2 = random(1234);
        Files.write(tmp.resolve("j-key.janus"), Janus.encrypt(Janus.Face.withKeys(p2,
                List.of(Keys.decodePublicKey(rustPub), javaKp.publicKey())), List.of(), rng));
        rustOpens("Java key file opens with the reference (its identity)", exe, tmp, "j-key.janus", p2, Map.of(), "-i", "rust.id");
        rustOpens("Java key file opens with the reference (Java identity file)", exe, tmp, "j-key.janus", p2, Map.of(), "-i", "java.id");

        byte[] decoy = random(3000), s1 = random(2000), s2 = random(100), s3 = random(0);
        Files.write(tmp.resolve("j-faces.janus"), Janus.encrypt(Janus.Face.withPassword(decoy, Bytes.ascii("leurre")), List.of(
                Janus.Face.withPassword(s1, Bytes.ascii("cache1")),
                Janus.Face.withKeys(s2, List.of(Keys.decodePublicKey(rustPub))),
                Janus.Face.withPassword(s3, Bytes.ascii("cache3"))), rng));
        rustOpens("Java decoy opens with the reference", exe, tmp, "j-faces.janus", decoy, Map.of("JANUS_MDP", "leurre"), "-m");
        rustOpens("Java hidden face 1 (password) opens with the reference", exe, tmp, "j-faces.janus", s1, Map.of("JANUS_MDP", "cache1"), "-m");
        rustOpens("Java hidden face 2 (key) opens with the reference", exe, tmp, "j-faces.janus", s2, Map.of(), "-i", "rust.id");
        rustOpens("Java hidden face 3 (password, empty) opens with the reference", exe, tmp, "j-faces.janus", s3, Map.of("JANUS_MDP", "cache3"), "-m");

        // Reference encrypts, Java decrypts.
        Files.write(tmp.resolve("p1.bin"), p1);
        r = rust(exe, tmp, Map.of("JANUS_MDP", "mot de passe é"), "chiffrer", "-m", "p1.bin", "r-pw.janus");
        check("reference encrypts with a password", r.code() == 0);
        byte[] rpw = Files.readAllBytes(tmp.resolve("r-pw.janus"));
        checkOpens("reference password file opens here", () -> Janus.decryptWithPassword(rpw, "mot de passe é".getBytes(StandardCharsets.UTF_8)), p1);

        Files.write(tmp.resolve("p2.bin"), p2);
        r = rust(exe, tmp, Map.of(), "chiffrer", "-r", javaPub, "p2.bin", "r-key.janus");
        check("reference encrypts to this client's public key", r.code() == 0);
        byte[] rkey = Files.readAllBytes(tmp.resolve("r-key.janus"));
        checkOpens("reference key file opens here", () -> Janus.decryptWithIdentities(rkey, List.of(javaKp)), p2);
        checkFails("reference key file: other identity fails here", () -> Janus.decryptWithIdentities(rkey, List.of(rustKp)));

        Files.write(tmp.resolve("decoy.bin"), decoy);
        Files.write(tmp.resolve("s1.bin"), s1);
        Files.write(tmp.resolve("s2.bin"), s2);
        Files.write(tmp.resolve("s3.bin"), s3);
        r = rust(exe, tmp, Map.of("JANUS_MDP", "leurre", "JANUS_MDP_CACHE", "un", "JANUS_MDP_CACHE2", "deux", "JANUS_MDP_CACHE3", "trois"),
                 "chiffrer", "-m", "decoy.bin", "r-faces.janus", "--cache", "-m", "s1.bin", "--cache", "-m", "s2.bin",
                 "--cache", "-m", "s3.bin");
        check("reference encrypts a decoy and 3 hidden faces", r.code() == 0);
        if (r.code() != 0) {
            System.out.println("         " + r.err().strip());
        }
        byte[] rf = Files.readAllBytes(tmp.resolve("r-faces.janus"));
        checkOpens("reference decoy opens here", () -> Janus.decryptWithPassword(rf, Bytes.ascii("leurre")), decoy);
        checkOpens("reference hidden face 1 opens here", () -> Janus.decryptWithPassword(rf, Bytes.ascii("un")), s1);
        checkOpens("reference hidden face 2 opens here", () -> Janus.decryptWithPassword(rf, Bytes.ascii("deux")), s2);
        checkOpens("reference hidden face 3 opens here", () -> Janus.decryptWithPassword(rf, Bytes.ascii("trois")), s3);

        r = rust(exe, tmp, Map.of("JANUS_MDP_CACHE", "secret"), "chiffrer", "-r", javaPub, "decoy.bin", "r-mixed.janus",
                 "--cache", "-m", "s1.bin");
        check("reference encrypts a key decoy with a password hidden face", r.code() == 0);
        byte[] rm = Files.readAllBytes(tmp.resolve("r-mixed.janus"));
        checkOpens("reference key decoy opens here", () -> Janus.decryptWithIdentities(rm, List.of(javaKp)), decoy);
        checkOpens("reference password hidden face opens here", () -> Janus.decryptWithPassword(rm, Bytes.ascii("secret")), s1);
    }

    private void rustOpens(String name, Path exe, Path tmp, String in, byte[] expected, Map<String, String> env,
                           String... cred) throws Exception {
        String out = "out-" + rng.nextInt(1 << 30) + ".bin";
        List<String> args = new ArrayList<>(List.of("dechiffrer"));
        args.addAll(List.of(cred));
        args.add(in);
        args.add(out);
        Result r = rust(exe, tmp, env, args.toArray(new String[0]));
        boolean ok = r.code() == 0 && Arrays.equals(Files.readAllBytes(tmp.resolve(out)), expected);
        check(name, ok);
        if (!ok) {
            System.out.println("         reference: " + r.code() + " " + r.err().strip());
        }
    }

    private void rustFails(String name, Path exe, Path tmp, String in, Map<String, String> env, String... cred) throws Exception {
        String out = "out-" + rng.nextInt(1 << 30) + ".bin";
        List<String> args = new ArrayList<>(List.of("dechiffrer"));
        args.addAll(List.of(cred));
        args.add(in);
        args.add(out);
        Result r = rust(exe, tmp, env, args.toArray(new String[0]));
        check(name, r.code() != 0 && !Files.exists(tmp.resolve(out)));
    }
    // ---- 8. Command line ---------------------------------------------------------------------

    private record Cli(int code, String out, String err) {
    }

    private static Cli cli(String... args) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
        int code = Main.run(args, new java.io.PrintStream(out, true, StandardCharsets.UTF_8),
                            new java.io.PrintStream(err, true, StandardCharsets.UTF_8));
        return new Cli(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private void commandLine() throws IOException {
        Path tmp = Files.createTempDirectory("janus-java-cli");
        try {
            String d = tmp.toString() + java.io.File.separator;
            byte[] plain = random(3000);
            Files.write(tmp.resolve("in.bin"), plain);
            Cli k = cli("keygen", d + "me.id");
            String pub = k.out().strip();
            check("keygen: status 0, prints the public key", k.code() == 0 && pub.startsWith("janus1"));
            byte[] idBefore = Files.readAllBytes(tmp.resolve("me.id"));
            check("keygen: refuses to overwrite an existing file (status 1, unchanged)",
                  cli("keygen", d + "me.id").code() == 1 && Arrays.equals(Files.readAllBytes(tmp.resolve("me.id")), idBefore));
            check("pubkey: same public key", cli("pubkey", d + "me.id").out().strip().equals(pub));

            check("encrypt to a key: status 0", cli("encrypt", d + "k.janus", d + "in.bin", "--to", pub).code() == 0);
            byte[] kFile = Files.readAllBytes(tmp.resolve("k.janus"));
            check("encrypt: refuses to overwrite an existing output (status 1, unchanged)",
                  cli("encrypt", d + "k.janus", d + "in.bin", "--to", pub).code() == 1
                  && Arrays.equals(Files.readAllBytes(tmp.resolve("k.janus")), kFile));
            check("decrypt with the identity: status 0, right plaintext",
                  cli("decrypt", d + "k.janus", d + "k.out", "--id", d + "me.id").code() == 0
                  && Arrays.equals(Files.readAllBytes(tmp.resolve("k.out")), plain));
            Files.write(tmp.resolve("existing.out"), new byte[] {1, 2, 3});
            check("decrypt: refuses to overwrite an existing output (status 1, unchanged)",
                  cli("decrypt", d + "k.janus", d + "existing.out", "--id", d + "me.id").code() == 1
                  && Arrays.equals(Files.readAllBytes(tmp.resolve("existing.out")), new byte[] {1, 2, 3}));
            Cli wrong = cli("decrypt", d + "k.janus", d + "wrong.out", "--pass", "nope");
            check("decrypt with a wrong credential: status 1, 'cannot decrypt', nothing written",
                  wrong.code() == 1 && wrong.err().strip().equals("cannot decrypt") && !Files.exists(tmp.resolve("wrong.out")));
            check("encrypt: repeated key in one face refused (status 1, nothing written)",
                  cli("encrypt", d + "r.janus", d + "in.bin", "--to", pub, "--to", pub).code() == 1
                  && !Files.exists(tmp.resolve("r.janus")));

            check("usage error: no arguments -> status 2", cli().code() == 2);
            check("usage error: unknown command -> status 2", cli("chiffrer").code() == 2);
            check("usage error: decrypt with an unknown option -> status 2",
                  cli("decrypt", d + "k.janus", d + "x.out", "--frobnicate", "x").code() == 2);
            check("usage error: hidden face without recipients -> status 2",
                  cli("encrypt", d + "x.janus", d + "in.bin", "--pass", "a", "--hidden", d + "in.bin").code() == 2);
        } finally {
            try (Stream<Path> st = Files.walk(tmp)) {
                st.sorted(Comparator.reverseOrder()).forEach(q -> q.toFile().delete());
            }
        }
    }
}
