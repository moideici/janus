using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Janus;

/// <summary>
/// The test suite (no test framework: the build must work offline without packages).
/// Run with: dotnet run -c Release --project clients/csharp/Janus -- selftest
/// </summary>
public static class SelfTest
{
    private static int _passed, _failed;

    public static int Run(string[] args)
    {
        string? vectorsDir = null, reference = null;
        bool quick = false;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--vectors" when i + 1 < args.Length: vectorsDir = args[++i]; break;
                case "--reference" when i + 1 < args.Length: reference = args[++i]; break;
                case "--quick": quick = true; break;
                default: Console.Error.WriteLine($"selftest: unknown option {args[i]}"); return 2;
            }
        }
        var root = FindRepositoryRoot();
        vectorsDir ??= root is null ? null : Path.Combine(root, "janus-rs", "vecteurs");
        reference ??= root is null ? null
            : Path.Combine(root, "janus-rs", "target", "release", OperatingSystem.IsWindows() ? "janus.exe" : "janus");

        var total = Stopwatch.StartNew();
        Section("Primitives (known answers)", Primitives);
        Section("X-Wing draft-11 test vector 1", XWingVector);
        Section("Curve25519, Elligator 2, Kemeleon", CurveAndEncodings);
        Section("Bech32m (BIP 350)", Bech32mVectors);
        if (vectorsDir is not null && File.Exists(Path.Combine(vectorsDir, "manifeste.json")))
        {
            Section("cles.json", () => KeyVectors(vectorsDir));
            Section("Reference vectors (manifeste.json)", () => FileVectors(vectorsDir, quick));
        }
        else
        {
            Fail("test vectors not found (use --vectors DIR)");
        }
        Section("Round trips", RoundTrips);
        if (reference is not null && File.Exists(reference))
            Section("Interoperability with the reference binary", () => Interop(reference));
        else
            Console.WriteLine($"\n(skipped: interoperability, reference binary not found at {reference ?? "?"})");

        Console.WriteLine($"\n{_passed} passed, {_failed} failed ({total.Elapsed.TotalSeconds:F1} s)");
        return _failed == 0 ? 0 : 1;
    }

    // ---- Helpers ----

    private static void Section(string title, Action body)
    {
        Console.WriteLine($"\n== {title}");
        var sw = Stopwatch.StartNew();
        try
        {
            body();
        }
        catch (Exception e)
        {
            Fail($"unexpected exception: {e}");
        }
        Console.WriteLine($"   ({sw.Elapsed.TotalSeconds:F2} s)");
    }

    private static void Check(string name, bool ok)
    {
        if (ok) { _passed++; Console.WriteLine($"ok    {name}"); }
        else Fail(name);
    }

    private static void Fail(string name)
    {
        _failed++;
        Console.WriteLine($"FAIL  {name}");
    }

    private static void CheckHex(string name, ReadOnlySpan<byte> actual, string expectedHex) =>
        Check(name, Convert.ToHexStringLower(actual) == expectedHex.Replace(" ", "").ToLowerInvariant());

    private static byte[] Hex(string s) => Convert.FromHexString(s.Replace(" ", ""));

    private static string Sha256Hex(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(SHA256.HashData(data));

    private static bool Throws<T>(Action action) where T : Exception
    {
        try { action(); return false; }
        catch (T) { return true; }
    }

    private static string? FindRepositoryRoot()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
                if (File.Exists(Path.Combine(dir.FullName, "janus-rs", "vecteurs", "manifeste.json")))
                    return dir.FullName;
        }
        return null;
    }

    private static byte[] MainPlaintext(int length)
    {
        var p = new byte[length];
        for (int k = 0; k < length; k++) p[k] = (byte)((31 * k + 7) % 256);
        return p;
    }

    private static byte[] HiddenPlaintext(int j, int length)
    {
        var p = new byte[length];
        for (int k = 0; k < length; k++) p[k] = (byte)((17 * k + 3 + 50 * j) % 256);
        return p;
    }

    private static byte[] Seed(byte value) => Enumerable.Repeat(value, 32).ToArray();

    // ---- 1. Primitives ----

    private static void Primitives()
    {
        CheckHex("SHA3-256(\"\")", Keccak.Sha3_256([]),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        CheckHex("SHA3-256(\"abc\")", Keccak.Sha3_256("abc"u8),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        CheckHex("SHA3-512(\"\")", Keccak.Sha3_512([]),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6" +
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
        CheckHex("SHAKE128(\"\", 32)", Keccak.Shake128([], 32),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        CheckHex("SHAKE256(\"\", 64)", Keccak.Shake256([], 64),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
        // Squeezing in pieces equals squeezing at once (crosses the 136-byte rate).
        var whole = Keccak.Shake256("janus"u8, 500);
        var xof = Keccak.NewShake256();
        xof.Absorb("jan"u8); xof.Absorb("us"u8);
        var parts = new byte[500];
        xof.Squeeze(parts.AsSpan(0, 7)); xof.Squeeze(parts.AsSpan(7, 300)); xof.Squeeze(parts.AsSpan(307));
        Check("SHAKE256 incremental absorb and squeeze", whole.AsSpan().SequenceEqual(parts));

        CheckHex("BLAKE2b-512(\"abc\") (RFC 7693)", Blake2b.Hash("abc"u8, 64),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");

        CheckHex("Poly1305 (RFC 8439 § 2.5.2)",
            Poly1305Tag(Hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
                        "Cryptographic Forum Research Group"u8),
            "a8061dc1305136c6c22b8baf0c0127a9");

        var key = Hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        var nonce = Hex("070000004041424344454647");
        var aad = Hex("50515253c0c1c2c3c4c5c6c7");
        var plaintext = Encoding.ASCII.GetBytes(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        var sealedData = ChaCha20Poly1305Aead.Seal(key, nonce, plaintext, aad);
        CheckHex("ChaCha20-Poly1305 ciphertext (RFC 8439 § 2.8.2)", sealedData.AsSpan(0, plaintext.Length),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
            "3ff4def08e4b7a9de576d26586cec64b6116");
        CheckHex("ChaCha20-Poly1305 tag (RFC 8439 § 2.8.2)", sealedData.AsSpan(plaintext.Length),
            "1ae10b594f09e26a7e902ecbd0600691");
        var opened = new byte[plaintext.Length];
        Check("ChaCha20-Poly1305 open", ChaCha20Poly1305Aead.Open(key, nonce, sealedData, aad, opened)
                                         && opened.AsSpan().SequenceEqual(plaintext));
        sealedData[5] ^= 1;
        Check("ChaCha20-Poly1305 rejects a modified ciphertext", !ChaCha20Poly1305Aead.Open(key, nonce, sealedData, aad, opened));

        var sw = Stopwatch.StartNew();
        var tag = Argon2id.Hash(Enumerable.Repeat((byte)1, 32).ToArray(), Enumerable.Repeat((byte)2, 16).ToArray(),
                                Enumerable.Repeat((byte)3, 8).ToArray(), Enumerable.Repeat((byte)4, 12).ToArray(),
                                32, 3, 4, 32);
        CheckHex($"Argon2id (RFC 9106 § 5.3) ({sw.ElapsedMilliseconds} ms)", tag,
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");

        sw.Restart();
        Argon2id.Janus("janus"u8, new byte[32]);
        Console.WriteLine($"      one Janus Argon2id (64 MiB, t=3, p=4): {sw.ElapsedMilliseconds} ms");
    }

    private static byte[] Poly1305Tag(byte[] key, ReadOnlySpan<byte> message)
    {
        var mac = new Poly1305(key);
        mac.Update(message[..5]);
        mac.Update(message[5..]);
        var tag = new byte[16];
        mac.Final(tag);
        return tag;
    }

    // ---- 2. X-Wing ----

    private static void XWingVector()
    {
        var seed = Hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        var eseed = Hex("3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2" +
                        "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2");
        const string expected = "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384";
        var id = new Identity(seed);
        var (ss, ctM, ctX) = XWing.EncapsulateDerand(id.PublicKey, eseed);
        CheckHex("X-Wing encapsulation shared secret", ss, expected);
        CheckHex("X-Wing decapsulation shared secret", XWing.Decapsulate(id, ctM, ctX), expected);

        // Implicit rejection: a modified ciphertext gives another secret, deterministically.
        var bad = ctM.ToArray();
        bad[0] ^= 1;
        var r1 = MlKem768.Decaps(id.DecapsulationKeyM, bad);
        var r2 = MlKem768.Decaps(id.DecapsulationKeyM, bad);
        Check("ML-KEM implicit rejection", r1.AsSpan().SequenceEqual(r2)
              && !r1.AsSpan().SequenceEqual(MlKem768.Decaps(id.DecapsulationKeyM, ctM)));

        // Encapsulation-key check: a coefficient ≥ q is refused.
        var pk = id.PublicKey.ToArray();
        pk[0] = 0xff; pk[1] |= 0x0f;                     // first 12-bit coefficient = 4095
        Check("ML-KEM encapsulation-key check rejects a coefficient ≥ q", !XWing.IsValidPublicKey(pk)
              && XWing.IsValidPublicKey(id.PublicKey));
    }

    // ---- Curve25519 / Elligator / Kemeleon ----

    private static void CurveAndEncodings()
    {
        CheckHex("X25519 (RFC 7748 § 5.2, vector 1)",
            Curve25519.X25519(Hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                              Hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        // u(G) generates the full group: ℓ·G has order 8, so u(ℓ·G) and u(2ℓ·G) are non-zero, u(8ℓ·G) = 0.
        bool IsZero(byte[] u) => u.All(b => b == 0);
        var gen = Curve25519.FullGroupGenerator;
        Check("u(G) has order 8ℓ", !IsZero(Curve25519.UnclampedLadder(Curve25519.L, gen))
              && !IsZero(Curve25519.UnclampedLadder(2 * Curve25519.L, gen))
              && IsZero(Curve25519.UnclampedLadder(8 * Curve25519.L, gen)));

        // Unclamped sender ladder and clamped recipient X25519 agree (§ 5.2 step 3).
        var recipient = new Identity(Seed(0x42));
        bool agree = true, roundTrip = true;
        int found = 0;
        for (int n = 0; n < 16; n++)
        {
            var s = RandomUniform.BigIntegerAtMost(8 * Curve25519.L - 1);
            var ctX = Curve25519.UnclampedLadder(s, Curve25519.FullGroupGenerator);
            var ssSender = Curve25519.UnclampedLadder(s, recipient.PublicX);
            agree &= ssSender.AsSpan().SequenceEqual(Curve25519.X25519(recipient.SecretX, ctX));
            var r = Curve25519.ElligatorRepresentative(ctX);
            if (r is null) continue;
            found++;
            roundTrip &= Curve25519.ElligatorMap(r).AsSpan().SequenceEqual(ctX);
        }
        Check("unclamped ladder (sender) = X25519 (recipient)", agree);
        Check($"Elligator 2 Map(Representative(u)) = u ({found} of 16 points had one)", roundTrip && found > 0);

        // Kemeleon round trip on a real ciphertext.
        var (_, ctM) = MlKem768.Encaps(recipient.PublicKey.AsSpan(0, MlKem768.EncapsulationKeySize));
        var encoded = Kemeleon.EncodeCiphertext(ctM);
        Check("Kemeleon DecodeCtxt(EncodeCtxt(ct)) = ct", Kemeleon.DecodeCiphertext(encoded).AsSpan().SequenceEqual(ctM));
        Check("Kemeleon encoding is randomized", !Kemeleon.EncodeCiphertext(ctM).AsSpan().SequenceEqual(encoded));
    }

    // ---- 3. Bech32m ----

    private static void Bech32mVectors()
    {
        foreach (var s in new[] { "A1LQFN3A", "a1lqfn3a", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "?1v759aa",
                                  "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
                                  "split1checkupstagehandshakeupstreamerranterredcaperredlc445v" })
            Check($"valid   {s}", Bech32m.Decode(s) is not null);
        foreach (var s in new[] { "a12uel5l", "A1lqfn3a", "qyrz8wqd2c9m", "1qyrz8wqd2c9m", "y1b0jsk6g", "lt1igcx5c0",
                                  "in1muywd", "mm1crxm3i", "au1s5cgom", "M1VUXWEZ", "16plkw9", "1p2gdwpf" })
            Check($"invalid {s}", Bech32m.Decode(s) is null);

        var id = new Identity(Seed(1));
        var idText = KeyText.EncodeIdentity(id.Seed);
        var pkText = KeyText.EncodePublicKey(id.PublicKey);
        Check("identity is 76 characters, public key 1958", idText.Length == 76 && pkText.Length == 1958);
        Check("identity accepted in lowercase", KeyText.DecodeIdentity(idText.ToLowerInvariant()) is not null);
        Check("mixed-case identity refused", KeyText.DecodeIdentity(idText[..20] + idText[20..].ToLowerInvariant()) is null);
        Check("public key refused as identity, identity refused as public key",
              KeyText.DecodeIdentity(pkText) is null && KeyText.DecodePublicKey(idText) is null);
        var badChecksum = idText[..^1] + (idText[^1] == 'Q' ? 'P' : 'Q');
        Check("identity with a wrong checksum refused", KeyText.DecodeIdentity(badChecksum) is null);
        // 31 bytes (wrong length) and non-zero padding.
        Check("wrong data length refused",
              KeyText.DecodeIdentity(Bech32m.Encode(KeyText.IdentityHrp, Bech32m.ToFiveBit(new byte[31]))) is null);
        var five = Bech32m.ToFiveBit(id.Seed);
        five[^1] |= 1;                                   // 256 bits in 52 groups: 4 padding bits
        Check("non-zero padding refused", KeyText.DecodeIdentity(Bech32m.Encode(KeyText.IdentityHrp, five)) is null);

        // § 3.1: pk_X must be canonical (bit 255 clear, value < p); canonical low-order points are accepted.
        byte[] WithPkX(byte[] x)
        {
            var pk = id.PublicKey.ToArray();
            x.CopyTo(pk, MlKem768.EncapsulationKeySize);
            return pk;
        }
        var top = id.PublicX.ToArray();
        top[31] |= 0x80;
        var pMinus = Curve25519.ToLittleEndian(Curve25519.P - 1);
        var pBytes = new byte[32];
        Curve25519.P.TryWriteBytes(pBytes, out _, isUnsigned: true, isBigEndian: false);
        var pPlus = pBytes.ToArray();
        pPlus[0] += 1;
        string Text(byte[] pk) => KeyText.EncodePublicKey(pk);
        Check("pk_X with bit 255 set refused", KeyText.DecodePublicKey(Text(WithPkX(top))) is null);
        Check("pk_X = p and p + 1 refused", KeyText.DecodePublicKey(Text(WithPkX(pBytes))) is null
              && KeyText.DecodePublicKey(Text(WithPkX(pPlus))) is null);
        Check("pk_X = p − 1, 0 and 1 (low order) accepted", KeyText.DecodePublicKey(Text(WithPkX(pMinus))) is not null
              && KeyText.DecodePublicKey(Text(WithPkX(new byte[32]))) is not null
              && KeyText.DecodePublicKey(Text(WithPkX(Curve25519.ToLittleEndian(1)))) is not null);
        Check("non-canonical pk_X refused by the encryptor", Throws<JanusException>(() =>
            JanusFile.Encrypt(Face.ForKeys([1, 2, 3], [WithPkX(top)]), [])));

        // § 3.3: identity files (BOM, CRLF, blanks; an invalid first identity line makes the file invalid).
        var dir = Directory.CreateTempSubdirectory("janus-csharp-id-").FullName;
        try
        {
            string file = Path.Combine(dir, "id");
            File.WriteAllText(file, (char)0xFEFF + "# comment\r\n\r\n  " + idText.ToLowerInvariant() + "  \r\n");
            Check("identity file with BOM, CRLF and blanks reads",
                  KeyText.ReadIdentityFile(file).Seed.AsSpan().SequenceEqual(id.Seed));
            string bad = idText[..^1] + (idText[^1] == 'Q' ? 'P' : 'Q');
            File.WriteAllText(file, "# comment\n" + bad + "\n" + idText + "\n");
            Check("identity file whose first identity line is invalid is refused",
                  Throws<JanusException>(() => KeyText.ReadIdentityFile(file)));

            // clients/README.md: keygen never overwrites; usage errors exit with status 2.
            var before = File.ReadAllBytes(file);
            var savedOut = Console.Out;
            var savedErr = Console.Error;
            Console.SetOut(TextWriter.Null);
            Console.SetError(TextWriter.Null);
            int keygenCode, usageCode, unknownCode;
            try
            {
                keygenCode = Program.Main(["keygen", file]);
                usageCode = Program.Main(["encrypt", Path.Combine(dir, "out")]);
                unknownCode = Program.Main(["frobnicate"]);
            }
            finally
            {
                Console.SetOut(savedOut);
                Console.SetError(savedErr);
            }
            Check("keygen refuses to overwrite an existing file", keygenCode == 1
                  && File.ReadAllBytes(file).AsSpan().SequenceEqual(before));
            Check("usage errors exit with status 2", usageCode == 2 && unknownCode == 2);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ---- 4. cles.json ----

    private static void KeyVectors(string dir)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "cles.json")));
        foreach (var entry in doc.RootElement.GetProperty("cles").EnumerateArray())
        {
            var seedHex = entry.GetProperty("graine").GetString()!;
            var id = new Identity(Convert.FromHexString(seedHex));
            string label = seedHex[..8] + "…";
            Check($"{label} identity string", KeyText.EncodeIdentity(id.Seed) == entry.GetProperty("identite").GetString());
            Check($"{label} public key string", KeyText.EncodePublicKey(id.PublicKey) == entry.GetProperty("cle_publique").GetString());
            Check($"{label} SHA-256 of pk", Sha256Hex(id.PublicKey) == entry.GetProperty("cle_publique_hex_sha256").GetString());
            var back = KeyText.DecodeIdentity(entry.GetProperty("identite").GetString()!);
            var pkBack = KeyText.DecodePublicKey(entry.GetProperty("cle_publique").GetString()!);
            Check($"{label} strings decode back", back is not null && back.AsSpan().SequenceEqual(id.Seed)
                  && pkBack is not null && pkBack.AsSpan().SequenceEqual(id.PublicKey));
        }
    }

    // ---- 5. Reference vectors ----

    private static void FileVectors(string dir, bool quick)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "manifeste.json")));
        var foreign = new Identity(Seed(0xEE));
        var sw = Stopwatch.StartNew();
        foreach (var v in doc.RootElement.GetProperty("vecteurs").EnumerateArray())
        {
            string name = v.GetProperty("fichier").GetString()!;
            var file = File.ReadAllBytes(Path.Combine(dir, name));
            Check($"{name}: size and SHA-256", file.Length == v.GetProperty("taille").GetInt64()
                  && Sha256Hex(file) == v.GetProperty("sha256_fichier").GetString());
            var opening = v.GetProperty("ouverture");
            string expected = v.GetProperty("sha256_clair").GetString()!;
            int expectedLength = v.GetProperty("clair_longueur").GetInt32();
            Identity IdentityFromHex(JsonElement e) => new(Convert.FromHexString(e.GetString()!));
            bool Matches(byte[] p, JsonElement face) => p.Length == face.GetProperty("clair_longueur").GetInt32()
                                                         && Sha256Hex(p) == face.GetProperty("sha256_clair").GetString();

            // Every field must be understood: an unknown one is a failure, never silently skipped.
            var openingFields = new HashSet<string> { "type", "valeur", "chacune_ouvre", "visages_caches", "plusieurs_visages" };
            foreach (var field in opening.EnumerateObject())
                if (!openingFields.Contains(field.Name)) Fail($"{name}: unknown field ouverture.{field.Name}");

            string type = opening.GetProperty("type").GetString()!;
            if (type == "mot_de_passe")
            {
                var p = JanusFile.DecryptWithPassword(file, Encoding.UTF8.GetBytes(opening.GetProperty("valeur").GetString()!));
                Check($"{name}: password opens the main face", p.Length == expectedLength && Sha256Hex(p) == expected);
            }
            else if (type == "identites")
            {
                var ids = opening.GetProperty("chacune_ouvre").EnumerateArray().Select(IdentityFromHex).ToList();
                bool all = ids.Count > 0;
                foreach (var id in ids)
                {
                    var p = JanusFile.DecryptWithIdentities(file, [id]);
                    all &= p.Length == expectedLength && Sha256Hex(p) == expected;
                }
                Check($"{name}: each of the {ids.Count} identities opens the main face", all);
                if (ids.Count > 1 && !quick)
                {
                    var p = JanusFile.DecryptWithIdentities(file, ids);
                    Check($"{name}: all {ids.Count} identities together open it once", Sha256Hex(p) == expected);
                }
            }
            else
            {
                Fail($"{name}: unknown opening type \"{type}\"");
            }

            if (opening.TryGetProperty("visages_caches", out var hidden))
            {
                var hiddenFields = new HashSet<string> { "mot_de_passe", "identite", "clair", "clair_longueur", "sha256_clair" };
                foreach (var h in hidden.EnumerateArray())
                {
                    foreach (var field in h.EnumerateObject())
                        if (!hiddenFields.Contains(field.Name)) Fail($"{name}: unknown hidden-face field {field.Name}");
                    bool byPassword = h.TryGetProperty("mot_de_passe", out var pw);
                    bool byIdentity = h.TryGetProperty("identite", out var seed);
                    if (byPassword == byIdentity)
                    {
                        Fail($"{name}: hidden face opened by neither or both of mot_de_passe and identite");
                        continue;
                    }
                    if (byPassword)
                    {
                        var hp = JanusFile.DecryptWithPassword(file, Encoding.UTF8.GetBytes(pw.GetString()!));
                        Check($"{name}: hidden face, password \"{pw.GetString()}\"", Matches(hp, h));
                    }
                    else
                    {
                        var hp = JanusFile.DecryptWithIdentities(file, [IdentityFromHex(seed)]);
                        Check($"{name}: hidden face, identity {seed.GetString()![..8]}…", Matches(hp, h));
                    }
                }
            }

            if (opening.TryGetProperty("plusieurs_visages", out var several))
            {
                var ids = several.EnumerateArray().Select(IdentityFromHex).ToList();
                bool severalError = false;
                try { JanusFile.DecryptWithIdentities(file, ids); }
                catch (DecryptionException e) { severalError = e.SeveralFaces; }
                Check($"{name}: {ids.Count} identities of different faces together → \"several faces\"", severalError);
            }

            Check($"{name}: wrong password fails",
                  Throws<DecryptionException>(() => JanusFile.DecryptWithPassword(file, "wrong"u8)));
            Check($"{name}: foreign identity fails",
                  Throws<DecryptionException>(() => JanusFile.DecryptWithIdentities(file, [foreign])));
        }
        Console.WriteLine($"      vector tests: {sw.Elapsed.TotalSeconds:F1} s");
    }

    // ---- 6. Round trips ----

    private static void RoundTrips()
    {
        var ids = Enumerable.Range(1, 17).Select(i => new Identity(Seed((byte)(0x60 + i)))).ToList();
        var pks = ids.Select(i => i.PublicKey).ToList();
        var foreign = new Identity(Seed(0xEE));
        var main = MainPlaintext(5000);
        var s1 = HiddenPlaintext(0, 700);
        var s2 = HiddenPlaintext(1, 3000);
        var s3 = HiddenPlaintext(2, 1);

        bool Opens(byte[] file, byte[] expected, Func<byte[], byte[]> open)
        {
            try { return open(file).AsSpan().SequenceEqual(expected); }
            catch (DecryptionException) { return false; }
        }

        // Password.
        var f = JanusFile.Encrypt(Face.ForPassword(main, "correct horse"), []);
        long reference = JanusFile.HeaderSize + JanusFile.EncryptedFaceSize(main.Length) + JanusFile.Reserve(main.Length);
        long bucket = JanusFile.Padme(reference);
        Check("password: file size in the PADME bucket of Ref", f.Length >= bucket && f.Length <= bucket + JanusFile.BucketMask(bucket));
        Check("password: opens", Opens(f, main, x => JanusFile.DecryptWithPassword(x, "correct horse"u8)));
        Check("password: wrong password fails", !Opens(f, main, x => JanusFile.DecryptWithPassword(x, "correct horsf"u8)));
        Check("password: an identity fails", !Opens(f, main, x => JanusFile.DecryptWithIdentities(x, [foreign])));

        // One key, sixteen keys.
        f = JanusFile.Encrypt(Face.ForKeys(main, [pks[0]]), []);
        Check("1 key: opens", Opens(f, main, x => JanusFile.DecryptWithIdentities(x, [ids[0]])));
        Check("1 key: foreign identity fails", !Opens(f, main, x => JanusFile.DecryptWithIdentities(x, [foreign])));
        var tampered = f.ToArray();
        tampered[JanusFile.HeaderSize + 10] ^= 1;
        Check("1 key: modified body fails", !Opens(tampered, main, x => JanusFile.DecryptWithIdentities(x, [ids[0]])));
        tampered = f.ToArray();
        tampered[200] ^= 1;
        Check("1 key: modified header fails", !Opens(tampered, main, x => JanusFile.DecryptWithIdentities(x, [ids[0]])));
        Check("1 key: truncated file fails", !Opens(f[..^1], main, x => JanusFile.DecryptWithIdentities(x, [ids[0]])));

        f = JanusFile.Encrypt(Face.ForKeys(main, pks.Take(16).ToList()), []);
        bool every = true;
        foreach (var id in ids.Take(16)) every &= Opens(f, main, x => JanusFile.DecryptWithIdentities(x, [id]));
        Check("16 keys: each identity opens", every);
        Check("16 keys: the 17th identity fails", !Opens(f, main, x => JanusFile.DecryptWithIdentities(x, [ids[16]])));

        // Sizes: empty, one full block, two blocks.
        foreach (int n in new[] { 0, 65536, 65537 })
        {
            var p = MainPlaintext(n);
            f = JanusFile.Encrypt(Face.ForKeys(p, [pks[1]]), []);
            Check($"{n}-byte plaintext round trip", Opens(f, p, x => JanusFile.DecryptWithIdentities(x, [ids[1]])));
        }

        // Decoy + 1 hidden face.
        f = JanusFile.Encrypt(Face.ForPassword(main, "decoy"), [Face.ForPassword(s1, "hidden")]);
        Check("decoy + 1 hidden: decoy opens", Opens(f, main, x => JanusFile.DecryptWithPassword(x, "decoy"u8)));
        Check("decoy + 1 hidden: hidden face opens", Opens(f, s1, x => JanusFile.DecryptWithPassword(x, "hidden"u8)));

        // Decoy + 3 hidden faces, mixing passwords and keys.
        f = JanusFile.Encrypt(Face.ForKeys(main, [pks[2], pks[3]]),
                              [Face.ForPassword(s1, "first"), Face.ForKeys(s2, [pks[4]]), Face.ForPassword(s3, "third")]);
        Check("decoy + 3 hidden: decoy opens (key 1 of 2)", Opens(f, main, x => JanusFile.DecryptWithIdentities(x, [ids[2]])));
        Check("decoy + 3 hidden: decoy opens (key 2 of 2)", Opens(f, main, x => JanusFile.DecryptWithIdentities(x, [ids[3]])));
        Check("decoy + 3 hidden: hidden password face", Opens(f, s1, x => JanusFile.DecryptWithPassword(x, "first"u8)));
        Check("decoy + 3 hidden: hidden key face", Opens(f, s2, x => JanusFile.DecryptWithIdentities(x, [ids[4]])));
        Check("decoy + 3 hidden: third hidden face", Opens(f, s3, x => JanusFile.DecryptWithPassword(x, "third"u8)));
        bool several = false;
        try { JanusFile.DecryptWithIdentities(f, [ids[2], ids[4]]); }
        catch (DecryptionException e) { several = e.SeveralFaces; }
        Check("decoy + 3 hidden: identities of two faces → \"several faces\"", several);
        Check("decoy + 3 hidden: decoy + two identities of the same face open once",
              Opens(f, main, x => JanusFile.DecryptWithIdentities(x, [ids[2], ids[3]])));

        // A hidden face of exactly the reserve size.
        long reserve = JanusFile.Reserve(main.Length);
        var exact = HiddenPlaintext(0, (int)(reserve - 16));                   // c(l) = l + 16 = Reserve
        f = JanusFile.Encrypt(Face.ForKeys(main, [pks[5]]), [Face.ForKeys(exact, [pks[6]])]);
        Check("hidden face filling the whole reserve", Opens(f, exact, x => JanusFile.DecryptWithIdentities(x, [ids[6]])));

        // Rule violations.
        Check("17 recipients refused (R3)", Throws<JanusException>(() =>
            JanusFile.Encrypt(Face.ForKeys(main, pks.Take(17).ToList()), [])));
        Check("17 recipients over several faces refused (R3)", Throws<JanusException>(() =>
            JanusFile.Encrypt(Face.ForKeys(main, pks.Take(15).ToList()),
                              [Face.ForPassword(s1, "a"), Face.ForKeys(s2, [pks[16]])])));
        Check("same password in two faces refused (R5)", Throws<JanusException>(() =>
            JanusFile.Encrypt(Face.ForPassword(main, "same"), [Face.ForPassword(s1, "same")])));
        Check("same public key in two faces refused (R5)", Throws<JanusException>(() =>
            JanusFile.Encrypt(Face.ForKeys(main, [pks[0]]), [Face.ForKeys(s1, [pks[0]])])));
        Check("hidden faces too big refused (R5)", Throws<JanusException>(() =>
            JanusFile.Encrypt(Face.ForKeys(main, [pks[0]]), [Face.ForKeys(HiddenPlaintext(0, (int)reserve - 15), [pks[1]])])));
        Check("hidden faces too big together refused (R5)", Throws<JanusException>(() =>
            JanusFile.Encrypt(Face.ForKeys(main, [pks[0]]),
                              [Face.ForKeys(HiddenPlaintext(0, 40000), [pks[1]]), Face.ForKeys(HiddenPlaintext(1, 40000), [pks[2]])])));
        Check("4 hidden faces refused", Throws<JanusException>(() =>
            JanusFile.Encrypt(Face.ForKeys(main, [pks[0]]),
                              [Face.ForKeys(s1, [pks[1]]), Face.ForKeys(s1, [pks[2]]), Face.ForKeys(s1, [pks[3]]), Face.ForKeys(s1, [pks[4]])])));
        var badKey = pks[0].ToArray();
        badKey[0] = 0xff; badKey[1] = 0xff;
        Check("invalid public key refused", Throws<JanusException>(() => JanusFile.Encrypt(Face.ForKeys(main, [badKey]), [])));
        Check("same public key twice in one face refused (R5)", Throws<JanusException>(() =>
            JanusFile.Encrypt(Face.ForKeys(main, [pks[0], pks[1], pks[0]]), [])));
        Check("file shorter than the header fails", Throws<DecryptionException>(() =>
            JanusFile.DecryptWithPassword(new byte[JanusFile.HeaderSize - 1], "x"u8)));
    }

    // ---- 7. Interoperability with the reference binary ----

    private static void Interop(string exe)
    {
        var dir = Directory.CreateTempSubdirectory("janus-csharp-interop-").FullName;
        try
        {
            string P(string name) => Path.Combine(dir, name);
            var decoy = RandomNumberGenerator.GetBytes(2_000_000);         // 31 STREAM blocks, reserve 125 000
            var secret1 = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("first secret ", 100)));
            var secret2 = RandomNumberGenerator.GetBytes(5000);
            var secret3 = RandomNumberGenerator.GetBytes(65537);
            File.WriteAllBytes(P("decoy"), decoy);
            File.WriteAllBytes(P("s1"), secret1);
            File.WriteAllBytes(P("s2"), secret2);
            File.WriteAllBytes(P("s3"), secret3);

            // Identities: one made by the reference tool, one by this client.
            var rust = RunTool(exe, ["cles", P("rust.id")], null);
            string rustPk = rust.stdout.Trim();
            var rustId = KeyText.ReadIdentityFile(P("rust.id"));
            Check("reference identity file reads here, same public key", rust.code == 0
                  && KeyText.EncodePublicKey(rustId.PublicKey) == rustPk);
            var mine = Identity.Generate();
            File.WriteAllText(P("mine.id"), KeyText.IdentityFile(mine));
            var pub = RunTool(exe, ["publique", P("mine.id")], null);
            Check("this client's identity file reads in the reference tool", pub.code == 0
                  && pub.stdout.Trim() == KeyText.EncodePublicKey(mine.PublicKey));

            bool RustOpens(string file, string output, byte[] expected, string? password, string? idFile)
            {
                var args = idFile is null ? new[] { "dechiffrer", "-m", file, P(output) } : new[] { "dechiffrer", "-i", idFile, file, P(output) };
                var env = password is null ? null : new Dictionary<string, string> { ["JANUS_MDP"] = password };
                var r = RunTool(exe, args, env);
                return r.code == 0 && File.Exists(P(output)) && File.ReadAllBytes(P(output)).AsSpan().SequenceEqual(expected);
            }

            // C# → reference.
            File.WriteAllBytes(P("c1.janus"), JanusFile.Encrypt(Face.ForPassword(secret1, "correct horse"), []));
            Check("C# → Rust: password", RustOpens(P("c1.janus"), "c1.out", secret1, "correct horse", null));
            Check("C# → Rust: wrong password fails", !RustOpens(P("c1.janus"), "c1.bad", secret1, "wrong", null));

            File.WriteAllBytes(P("c2.janus"), JanusFile.Encrypt(Face.ForKeys(decoy, [rustId.PublicKey]), []));
            Check("C# → Rust: public key", RustOpens(P("c2.janus"), "c2.out", decoy, null, P("rust.id")));

            File.WriteAllBytes(P("c3.janus"), JanusFile.Encrypt(Face.ForPassword(decoy, "decoy"),
                [Face.ForPassword(secret1, "hidden-1"), Face.ForKeys(secret2, [rustId.PublicKey]), Face.ForPassword(secret3, "hidden-3")]));
            Check("C# → Rust: decoy + 3 hidden faces, decoy", RustOpens(P("c3.janus"), "c3.0", decoy, "decoy", null));
            Check("C# → Rust: hidden password face 1", RustOpens(P("c3.janus"), "c3.1", secret1, "hidden-1", null));
            Check("C# → Rust: hidden key face 2", RustOpens(P("c3.janus"), "c3.2", secret2, null, P("rust.id")));
            Check("C# → Rust: hidden password face 3 (2 blocks)", RustOpens(P("c3.janus"), "c3.3", secret3, "hidden-3", null));

            // Reference → C#.
            string minePk = KeyText.EncodePublicKey(mine.PublicKey);
            var r1 = RunTool(exe, ["chiffrer", "-m", P("s1"), P("r1.janus")], new() { ["JANUS_MDP"] = "correct horse" });
            Check("Rust → C#: password", r1.code == 0
                  && JanusFile.DecryptWithPassword(File.ReadAllBytes(P("r1.janus")), "correct horse"u8).AsSpan().SequenceEqual(secret1));
            Check("Rust → C#: wrong password fails", Throws<DecryptionException>(() =>
                  JanusFile.DecryptWithPassword(File.ReadAllBytes(P("r1.janus")), "wrong"u8)));

            var r2 = RunTool(exe, ["chiffrer", "-r", minePk, P("decoy"), P("r2.janus")], null);
            Check("Rust → C#: public key", r2.code == 0
                  && JanusFile.DecryptWithIdentities(File.ReadAllBytes(P("r2.janus")), [mine]).AsSpan().SequenceEqual(decoy));

            var r3 = RunTool(exe, ["chiffrer", "-m", P("decoy"), P("r3.janus"),
                                   "--cache", "-m", P("s1"), "--cache", "-r", minePk, P("s2"), "--cache", "-m", P("s3")],
                             new() { ["JANUS_MDP"] = "decoy", ["JANUS_MDP_CACHE"] = "hidden-1", ["JANUS_MDP_CACHE3"] = "hidden-3" });
            if (r3.code != 0) Console.WriteLine($"      reference tool: {r3.stderr.Trim()}");
            var r3File = r3.code == 0 ? File.ReadAllBytes(P("r3.janus")) : [];
            Check("Rust → C#: decoy + 3 hidden faces, decoy", r3.code == 0
                  && JanusFile.DecryptWithPassword(r3File, "decoy"u8).AsSpan().SequenceEqual(decoy));
            Check("Rust → C#: hidden password face 1", r3.code == 0
                  && JanusFile.DecryptWithPassword(r3File, "hidden-1"u8).AsSpan().SequenceEqual(secret1));
            Check("Rust → C#: hidden key face 2", r3.code == 0
                  && JanusFile.DecryptWithIdentities(r3File, [mine]).AsSpan().SequenceEqual(secret2));
            Check("Rust → C#: hidden password face 3", r3.code == 0
                  && JanusFile.DecryptWithPassword(r3File, "hidden-3"u8).AsSpan().SequenceEqual(secret3));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }

    private static (int code, string stdout, string stderr) RunTool(string exe, string[] args, Dictionary<string, string>? env)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        foreach (var name in new[] { "JANUS_MDP", "JANUS_MDP_CACHE", "JANUS_MDP_CACHE2", "JANUS_MDP_CACHE3" })
            psi.Environment.Remove(name);
        if (env is not null) foreach (var (k, v) in env) psi.Environment[k] = v;
        using var process = Process.Start(psi)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(600_000)) { process.Kill(); return (-1, "", "timeout"); }
        return (process.ExitCode, stdout.Result, stderr.Result);
    }
}
