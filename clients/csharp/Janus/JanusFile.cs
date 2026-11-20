using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Janus;

/// <summary>A user-facing error (bad arguments, rule violation, unreadable key…).</summary>
public class JanusException(string message) : Exception(message);

/// <summary>The single decryption error, or the "several faces" error of spec § 8 step 4.</summary>
public sealed class DecryptionException(bool severalFaces)
    : JanusException(severalFaces ? "these credentials open several faces" : "cannot decrypt")
{
    public bool SeveralFaces { get; } = severalFaces;
}

/// <summary>One face to encrypt: a plaintext and either one password or 1 to 16 public keys.</summary>
public sealed class Face
{
    public byte[] Plaintext { get; }
    public byte[]? Password { get; }
    public IReadOnlyList<byte[]> PublicKeys { get; }

    private Face(byte[] plaintext, byte[]? password, IReadOnlyList<byte[]> publicKeys)
    {
        Plaintext = plaintext;
        Password = password;
        PublicKeys = publicKeys;
    }

    public static Face ForPassword(byte[] plaintext, byte[] password) => new(plaintext, password, Array.Empty<byte[]>());
    public static Face ForPassword(byte[] plaintext, string password) => ForPassword(plaintext, Encoding.UTF8.GetBytes(password));
    public static Face ForKeys(byte[] plaintext, IReadOnlyList<byte[]> publicKeys) => new(plaintext, null, publicKeys);

    public int RecipientCount => Password is null ? PublicKeys.Count : 1;
}

/// <summary>The Janus v1 file format (spec § 6–8).</summary>
public static class JanusFile
{
    public const int SlotCount = 16;                       // N_SLOTS
    public const int TagCount = 4;                         // N_TAGS
    public const int SlotSize = 1632;                      // S
    public const int HeaderSize = 32 * TagCount + 32 + SlotCount * SlotSize;   // H = 26 272
    public const int BlockSize = 65536;                    // TB
    public const long MinReserve = 65536;                  // R_MIN
    public const long ReserveRatio = 16;                   // RHO
    public const int MaxHiddenFaces = TagCount - 1;

    private const int SaltOffset = 32 * TagCount;          // 128
    private const int SlotsOffset = SaltOffset + 32;       // 160
    private const int WrapOffset = 1568;                   // W inside a slot
    private const int WrapSize = 64;
    private const int TripleSize = 48;                     // K ‖ BE64(d) ‖ BE64(l)

    private static readonly byte[] LabelHeader = "janus/v1/entete"u8.ToArray();
    private static readonly byte[] LabelBody = "janus/v1/corps"u8.ToArray();
    private static readonly byte[] LabelWrapKey = "janus/v1/emballage/xwing"u8.ToArray();
    private static readonly byte[] LabelWrapPassword = "janus/v1/emballage/mdp"u8.ToArray();

    // ---- Sizes (§ 6) ----

    public static long Blocks(long l) => Math.Max(1, (l + BlockSize - 1) / BlockSize);
    public static long EncryptedFaceSize(long l) => l + 16 * Blocks(l);
    public static long Reserve(long l1) => Math.Max(MinReserve, (l1 + ReserveRatio - 1) / ReserveRatio);

    public static long Padme(long l)
    {
        if (l < 2) return l;
        int e = 63 - System.Numerics.BitOperations.LeadingZeroCount((ulong)l);
        int s = 32 - System.Numerics.BitOperations.LeadingZeroCount((uint)e);   // ⌊log2 E⌋ + 1
        long mask = (1L << (e - s)) - 1;
        return (l + mask) & ~mask;
    }

    // ---- Primitives ----

    private static byte[] Hkdf(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> info)
    {
        var output = new byte[32];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, ReadOnlySpan<byte>.Empty, info);
        return output;
    }

    private static byte[] WrapKey(ReadOnlySpan<byte> secret, byte[] label, int slot)
    {
        var info = new byte[label.Length + 1];
        label.CopyTo(info, 0);
        info[^1] = (byte)slot;
        return Hkdf(secret, info);
    }

    /// <summary>T = HMAC-SHA-256(HKDF(K, "janus/v1/entete"), BE64(F) ‖ BE64(d) ‖ BE64(l) ‖ header[128:H]).</summary>
    private static byte[] HeaderTag(ReadOnlySpan<byte> triple, byte[] macInput, long fileSize)
    {
        // macInput = 24 bytes of room ‖ header[128:H]; the first 24 bytes are rewritten for each tag.
        BinaryPrimitives.WriteUInt64BigEndian(macInput, (ulong)fileSize);
        triple.Slice(32, 16).CopyTo(macInput.AsSpan(8));
        var key = Hkdf(triple[..32], LabelHeader);
        var tag = HMACSHA256.HashData(key, macInput);
        CryptographicOperations.ZeroMemory(key);
        return tag;
    }

    private static byte[] MacInput(ReadOnlySpan<byte> header)
    {
        var input = new byte[24 + HeaderSize - SaltOffset];
        header[SaltOffset..HeaderSize].CopyTo(input.AsSpan(24));
        return input;
    }

    private static byte[] FaceNonce(long block, bool last)
    {
        var nonce = new byte[12];
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(3), (ulong)block);
        nonce[11] = (byte)(last ? 1 : 0);
        return nonce;
    }

    // ---- Encryption (§ 7) ----

    public static byte[] Encrypt(Face main, IReadOnlyList<Face> hidden)
    {
        CheckRules(main, hidden);
        var faces = new List<Face> { main };
        faces.AddRange(hidden);

        // 1. File size and offsets.
        long l1 = main.Plaintext.Length;
        long reference = HeaderSize + EncryptedFaceSize(l1) + Reserve(l1);
        long fileSize = (long)RandomUniform.UInt64InRange((ulong)reference, (ulong)Padme(reference));
        long bodySize = fileSize - HeaderSize;
        var offsets = new long[faces.Count];
        offsets[0] = 0;
        if (hidden.Count > 0)
        {
            long free = bodySize - EncryptedFaceSize(l1) - hidden.Sum(f => EncryptedFaceSize(f.Plaintext.Length));
            var order = RandomUniform.Permutation(hidden.Count);
            var b = Enumerable.Range(0, hidden.Count)
                              .Select(_ => (long)RandomUniform.UInt64InRange(0, (ulong)free))
                              .OrderBy(x => x).ToArray();
            long placed = 0;
            for (int m = 0; m < hidden.Count; m++)
            {
                int j = order[m];
                offsets[1 + j] = EncryptedFaceSize(l1) + b[m] + placed;
                placed += EncryptedFaceSize(hidden[j].Plaintext.Length);
            }
        }

        // 2. Random header (and body); the salt is header[128:160].
        var file = RandomNumberGenerator.GetBytes(checked((int)fileSize));
        var salt = file.AsSpan(SaltOffset, 32).ToArray();

        // 3–4. Slots.
        var slotOrder = RandomUniform.Permutation(SlotCount);
        int nextSlot = 0;
        var fileKeys = new List<byte[]>();
        for (int f = 0; f < faces.Count; f++)
        {
            var face = faces[f];
            var fileKey = RandomNumberGenerator.GetBytes(32);
            fileKeys.Add(fileKey);
            var triple = Triple(fileKey, offsets[f], face.Plaintext.Length);

            if (face.Password is not null)
            {
                int i = slotOrder[nextSlot++];
                var a = Argon2id.Janus(face.Password, salt);
                WriteWrap(file, i, WrapKey(a, LabelWrapPassword, i), triple);
                CryptographicOperations.ZeroMemory(a);
            }
            else
            {
                foreach (var pk in face.PublicKeys)
                {
                    int i = slotOrder[nextSlot++];
                    var (ss, prefix) = XWing.EncapsulateHidden(pk);
                    prefix.CopyTo(file, SlotsOffset + SlotSize * i);
                    WriteWrap(file, i, WrapKey(ss, LabelWrapKey, i), triple);
                    CryptographicOperations.ZeroMemory(ss);
                }
            }
            CryptographicOperations.ZeroMemory(triple);
        }

        // 5. Header tags, at a random permutation of the 4 positions.
        var tagOrder = RandomUniform.Permutation(TagCount);
        var macInput = MacInput(file.AsSpan(0, HeaderSize));
        for (int f = 0; f < faces.Count; f++)
        {
            var triple = Triple(fileKeys[f], offsets[f], faces[f].Plaintext.Length);
            HeaderTag(triple, macInput, fileSize).CopyTo(file, 32 * tagOrder[f]);
            CryptographicOperations.ZeroMemory(triple);
        }

        // 6. Body: each face at H + d; the rest stays random.
        for (int f = 0; f < faces.Count; f++)
        {
            EncryptFace(fileKeys[f], faces[f].Plaintext, file.AsSpan(checked((int)(HeaderSize + offsets[f]))));
            CryptographicOperations.ZeroMemory(fileKeys[f]);
        }
        return file;
    }

    private static void CheckRules(Face main, IReadOnlyList<Face> hidden)
    {
        if (hidden.Count > MaxHiddenFaces) throw new JanusException($"at most {MaxHiddenFaces} hidden faces");
        var faces = new List<Face> { main };
        faces.AddRange(hidden);

        foreach (var face in faces)
        {
            if (face.Password is null && face.PublicKeys.Count == 0) throw new JanusException("a face has no recipient");
            // R1 holds by construction: a password face holds exactly one password and no key.
            foreach (var pk in face.PublicKeys)
                if (!XWing.IsValidPublicKey(pk)) throw new JanusException("invalid public key");
        }
        // R3
        if (faces.Sum(f => f.RecipientCount) > SlotCount)
            throw new JanusException($"at most {SlotCount} recipients over all faces");
        // R5: reserve
        long l1 = main.Plaintext.Length;
        if (hidden.Sum(f => EncryptedFaceSize(f.Plaintext.Length)) > Reserve(l1))
            throw new JanusException($"the hidden faces do not fit in the reserve ({Reserve(l1)} bytes)");
        // R5: a public key appears once in a face (SHOULD), and in one face only (MUST)
        foreach (var face in faces)
            for (int a = 0; a < face.PublicKeys.Count; a++)
                for (int b = a + 1; b < face.PublicKeys.Count; b++)
                    if (face.PublicKeys[a].AsSpan().SequenceEqual(face.PublicKeys[b]))
                        throw new JanusException("a public key appears twice in a face");
        // R5: no shared password, no public key in two faces
        for (int a = 0; a < faces.Count; a++)
            for (int b = a + 1; b < faces.Count; b++)
            {
                if (faces[a].Password is { } pa && faces[b].Password is { } pb && pa.AsSpan().SequenceEqual(pb))
                    throw new JanusException("two faces share a password");
                foreach (var ka in faces[a].PublicKeys)
                    foreach (var kb in faces[b].PublicKeys)
                        if (ka.AsSpan().SequenceEqual(kb)) throw new JanusException("a public key appears in two faces");
            }
    }

    private static byte[] Triple(ReadOnlySpan<byte> fileKey, long d, long l)
    {
        var triple = new byte[TripleSize];
        fileKey.CopyTo(triple);
        BinaryPrimitives.WriteUInt64BigEndian(triple.AsSpan(32), (ulong)d);
        BinaryPrimitives.WriteUInt64BigEndian(triple.AsSpan(40), (ulong)l);
        return triple;
    }

    private static void WriteWrap(byte[] file, int slot, byte[] wrapKey, ReadOnlySpan<byte> triple)
    {
        var w = file.AsSpan(SlotsOffset + SlotSize * slot + WrapOffset, WrapSize);
        ChaCha20Poly1305Aead.Seal(wrapKey, new byte[12], triple, ReadOnlySpan<byte>.Empty, w);
        CryptographicOperations.ZeroMemory(wrapKey);
    }

    /// <summary>STREAM encryption of one face (§ 7.1) into output (c(l) bytes).</summary>
    private static void EncryptFace(ReadOnlySpan<byte> fileKey, ReadOnlySpan<byte> plaintext, Span<byte> output)
    {
        var bodyKey = Hkdf(fileKey, LabelBody);
        long blocks = Blocks(plaintext.Length);
        for (long j = 0; j < blocks; j++)
        {
            int start = (int)(j * BlockSize);
            int length = Math.Min(BlockSize, plaintext.Length - start);
            ChaCha20Poly1305Aead.Seal(bodyKey, FaceNonce(j, j == blocks - 1), plaintext.Slice(start, length),
                                      ReadOnlySpan<byte>.Empty, output.Slice(start + 16 * (int)j, length + 16));
        }
        CryptographicOperations.ZeroMemory(bodyKey);
    }

    // ---- Decryption (§ 8) ----

    public static byte[] DecryptWithPassword(ReadOnlySpan<byte> file, ReadOnlySpan<byte> password)
    {
        if (file.Length < HeaderSize) throw new DecryptionException(false);
        var a = Argon2id.Janus(password, file.Slice(SaltOffset, 32));
        var keys = new List<byte[]>(SlotCount);
        for (int i = 0; i < SlotCount; i++) keys.Add(WrapKey(a, LabelWrapPassword, i));
        CryptographicOperations.ZeroMemory(a);
        return Decrypt(file, keys);
    }

    public static byte[] DecryptWithIdentities(ReadOnlySpan<byte> file, IReadOnlyList<Identity> identities)
    {
        if (identities.Count == 0) throw new JanusException("no identity given");
        if (file.Length < HeaderSize) throw new DecryptionException(false);
        var keys = new List<byte[]>(SlotCount * identities.Count);
        for (int i = 0; i < SlotCount; i++)
        {
            var slot = file.Slice(SlotsOffset + SlotSize * i, SlotSize);
            foreach (var id in identities)
            {
                var ss = XWing.DecapsulateHidden(id, slot[..WrapOffset]);
                keys.Add(WrapKey(ss, LabelWrapKey, i));
                CryptographicOperations.ZeroMemory(ss);
            }
        }
        return Decrypt(file, keys);
    }

    /// <summary>
    /// Steps 2–7 of § 8. wrapKeys holds one candidate key per attempt, slot-major: attempt n uses
    /// slot n / (count / 16). Every attempt does the same work, whether it succeeds or not.
    /// </summary>
    private static byte[] Decrypt(ReadOnlySpan<byte> file, List<byte[]> wrapKeys)
    {
        long fileSize = file.Length;
        var header = file[..HeaderSize];
        var macInput = MacInput(header);
        int perSlot = wrapKeys.Count / SlotCount;
        var nonce = new byte[12];
        var valid = new List<byte[]>();

        for (int n = 0; n < wrapKeys.Count; n++)
        {
            int slot = n / perSlot;
            var w = header.Slice(SlotsOffset + SlotSize * slot + WrapOffset, WrapSize);
            var triple = new byte[TripleSize];
            bool opened = ChaCha20Poly1305Aead.Open(wrapKeys[n], nonce, w, ReadOnlySpan<byte>.Empty, triple);
            if (!opened) Array.Clear(triple);                  // 48 zero bytes on failure
            CryptographicOperations.ZeroMemory(wrapKeys[n]);

            var tag = HeaderTag(triple, macInput, fileSize);
            bool matches = false;
            for (int t = 0; t < TagCount; t++)
                matches |= CryptographicOperations.FixedTimeEquals(tag, header.Slice(32 * t, 32));

            if (opened && matches) valid.Add(triple);
            else CryptographicOperations.ZeroMemory(triple);
        }

        // Deduplicate on the full triple (K, d, l).
        var distinct = new List<byte[]>();
        foreach (var t in valid)
            if (!distinct.Any(x => CryptographicOperations.FixedTimeEquals(x, t))) distinct.Add(t);
        if (distinct.Count == 0) throw new DecryptionException(false);
        if (distinct.Count > 1) throw new DecryptionException(true);

        var chosen = distinct[0];
        ulong d = BinaryPrimitives.ReadUInt64BigEndian(chosen.AsSpan(32));
        ulong l = BinaryPrimitives.ReadUInt64BigEndian(chosen.AsSpan(40));

        // Bounds, without overflow.
        UInt128 blocks = l == 0 ? 1 : ((UInt128)l + BlockSize - 1) / BlockSize;
        if ((UInt128)d + l + 16 * blocks > (UInt128)(ulong)(fileSize - HeaderSize)) throw new DecryptionException(false);

        var bodyKey = Hkdf(chosen.AsSpan(0, 32), LabelBody);
        foreach (var t in valid) CryptographicOperations.ZeroMemory(t);
        var plaintext = new byte[(int)l];
        var faceData = file.Slice(HeaderSize + (int)d, (int)(l + 16 * (ulong)blocks));
        for (long j = 0; j < (long)blocks; j++)
        {
            int start = (int)(j * BlockSize);
            int length = (int)Math.Min(BlockSize, (long)l - start);
            bool ok = ChaCha20Poly1305Aead.Open(bodyKey, FaceNonce(j, j == (long)blocks - 1),
                                                faceData.Slice(start + 16 * (int)j, length + 16),
                                                ReadOnlySpan<byte>.Empty, plaintext.AsSpan(start, length));
            if (!ok)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                CryptographicOperations.ZeroMemory(bodyKey);
                throw new DecryptionException(false);
            }
        }
        CryptographicOperations.ZeroMemory(bodyKey);
        return plaintext;
    }
}
