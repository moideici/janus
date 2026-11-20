using System.Text;

namespace Janus;

/// <summary>The common command line of clients/README.md, plus "selftest".</summary>
public static class Program
{
    private const string Usage = """
        Janus v1 C# client (interoperability prototype, not audited, not constant-time).

        usage:
          janus keygen IDENTITY_FILE
          janus pubkey IDENTITY_FILE
          janus encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...
          janus decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)
          janus selftest [--vectors DIR] [--reference JANUS_EXE] [--quick]

        RECIPIENTS := --pass PASSWORD | (--to PUBLIC_KEY | --to-file FILE)+
        """;

    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            Console.Out.WriteLine(Usage);
            return args.Length == 0 ? 2 : 0;
        }
        try
        {
            return args[0] switch
            {
                "keygen" => Keygen(args),
                "pubkey" => Pubkey(args),
                "encrypt" => Encrypt(args),
                "decrypt" => Decrypt(args),
                "selftest" => SelfTest.Run(args[1..]),
                _ => UsageError($"unknown command: {args[0]}"),
            };
        }
        catch (DecryptionException e)
        {
            Console.Error.WriteLine(e.Message);
            return 1;
        }
        catch (Exception e) when (e is JanusException or IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"janus: {e.Message}");
            return 1;
        }
    }

    private static int UsageError(string message)
    {
        Console.Error.WriteLine($"janus: {message}");
        Console.Error.WriteLine(Usage);
        return 2;
    }

    private static int Keygen(string[] args)
    {
        if (args.Length != 2) return UsageError("keygen takes one identity file");
        var id = Identity.Generate();
        using (var stream = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write))
        {
            var bytes = Encoding.UTF8.GetBytes(KeyText.IdentityFile(id));
            stream.Write(bytes);
        }
        Console.Out.WriteLine(KeyText.EncodePublicKey(id.PublicKey));
        return 0;
    }

    private static int Pubkey(string[] args)
    {
        if (args.Length != 2) return UsageError("pubkey takes one identity file");
        var id = KeyText.ReadIdentityFile(args[1]);
        Console.Out.WriteLine(KeyText.EncodePublicKey(id.PublicKey));
        return 0;
    }

    private static int Encrypt(string[] args)
    {
        if (args.Length < 4) return UsageError("encrypt needs OUTPUT INPUT RECIPIENTS");
        string output = args[1];
        var faces = new List<Face>();
        int i = 2;
        while (i < args.Length)
        {
            if (faces.Count > 0)
            {
                if (args[i] != "--hidden") return UsageError($"unexpected argument: {args[i]}");
                i++;
                if (i >= args.Length) return UsageError("--hidden needs INPUT RECIPIENTS");
            }
            byte[] plaintext = File.ReadAllBytes(args[i++]);
            byte[]? password = null;
            var keys = new List<byte[]>();
            while (i < args.Length && args[i] != "--hidden")
            {
                string option = args[i];
                if (i + 1 >= args.Length) return UsageError($"{option} needs a value");
                string value = args[i + 1];
                i += 2;
                switch (option)
                {
                    case "--pass":
                        if (password is not null) return UsageError("a face has at most one password (rule R1)");
                        password = Encoding.UTF8.GetBytes(value);
                        break;
                    case "--to":
                        keys.Add(KeyText.DecodePublicKey(value) ?? throw new JanusException("invalid public key"));
                        break;
                    case "--to-file":
                        keys.AddRange(KeyText.ReadPublicKeyFile(value));
                        break;
                    default:
                        return UsageError($"unknown option: {option}");
                }
            }
            if (password is not null && keys.Count > 0)
                return UsageError("a password is alone in its face (rule R1)");
            if (password is null && keys.Count == 0) return UsageError("a face needs recipients");
            faces.Add(password is not null ? Face.ForPassword(plaintext, password) : Face.ForKeys(plaintext, keys));
        }

        var file = JanusFile.Encrypt(faces[0], faces.Skip(1).ToList());
        File.WriteAllBytes(output, file);
        return 0;
    }

    private static int Decrypt(string[] args)
    {
        if (args.Length < 5) return UsageError("decrypt needs INPUT OUTPUT and a credential");
        string input = args[1], output = args[2];
        byte[]? password = null;
        var identities = new List<Identity>();
        for (int i = 3; i < args.Length; i += 2)
        {
            if (i + 1 >= args.Length) return UsageError($"{args[i]} needs a value");
            switch (args[i])
            {
                case "--pass":
                    if (password is not null) return UsageError("one password at most");
                    password = Encoding.UTF8.GetBytes(args[i + 1]);
                    break;
                case "--id":
                    identities.Add(KeyText.ReadIdentityFile(args[i + 1]));
                    break;
                default:
                    return UsageError($"unknown option: {args[i]}");
            }
        }
        if ((password is null) == (identities.Count == 0))
            return UsageError("give either --pass or one or more --id");

        byte[] file;
        try
        {
            file = File.ReadAllBytes(input);
        }
        catch (IOException)
        {
            throw new DecryptionException(false);
        }
        // Everything is decrypted and verified in memory; nothing is written on failure.
        var plaintext = password is not null
            ? JanusFile.DecryptWithPassword(file, password)
            : JanusFile.DecryptWithIdentities(file, identities);
        File.WriteAllBytes(output, plaintext);
        return 0;
    }
}
