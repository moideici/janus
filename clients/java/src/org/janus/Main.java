package org.janus;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** The common command line of the Janus clients (clients/README.md). */
public final class Main {

    private static final String USAGE = String.join("\n",
        "Janus v1 - Java interoperability client (research prototype, not audited, not constant-time)",
        "",
        "usage:",
        "  janus keygen IDENTITY_FILE",
        "  janus pubkey IDENTITY_FILE",
        "  janus encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...",
        "  janus decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)",
        "  janus selftest [REPOSITORY_ROOT]",
        "",
        "RECIPIENTS := --pass PASSWORD | (--to PUBLIC_KEY | --to-file FILE)+");

    private Main() {
    }

    /** A usage error: exit status 2. */
    private static final class UsageException extends Exception {
        private static final long serialVersionUID = 1L;

        UsageException(String message) {
            super(message);
        }
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
            (args.length == 0 ? err : out).println(USAGE);
            return args.length == 0 ? 2 : 0;
        }
        try {
            switch (args[0]) {
                case "keygen" -> keygen(args, out);
                case "pubkey" -> pubkey(args, out);
                case "encrypt" -> encrypt(args);
                case "decrypt" -> decrypt(args);
                case "selftest" -> {
                    return Tests.run(Arrays.copyOfRange(args, 1, args.length));
                }
                default -> throw new UsageException("unknown command: " + args[0]);
            }
            return 0;
        } catch (UsageException e) {
            err.println("janus: " + e.getMessage());
            err.println(USAGE);
            return 2;
        } catch (Janus.JanusException e) {
            err.println(e.getMessage());
            return 1;
        } catch (IOException | IllegalArgumentException e) {
            err.println("janus: " + e.getMessage());
            return 1;
        }
    }

    private static void keygen(String[] args, PrintStream out) throws UsageException, IOException {
        if (args.length != 2) {
            throw new UsageException("keygen takes one identity file");
        }
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        XWing.KeyPair kp = new XWing.KeyPair(seed);
        String text = Keys.identityFileText(seed, kp.publicKey());
        writeNew(Path.of(args[1]), text.getBytes(StandardCharsets.UTF_8));
        out.println(Keys.encodePublicKey(kp.publicKey()));
        Arrays.fill(seed, (byte) 0);
        kp.wipe();
    }

    private static void pubkey(String[] args, PrintStream out) throws UsageException, IOException {
        if (args.length != 2) {
            throw new UsageException("pubkey takes one identity file");
        }
        byte[] seed = Keys.readIdentityFile(Path.of(args[1]));
        XWing.KeyPair kp = new XWing.KeyPair(seed);
        out.println(Keys.encodePublicKey(kp.publicKey()));
        Arrays.fill(seed, (byte) 0);
        kp.wipe();
    }

    private static void encrypt(String[] args) throws UsageException, IOException, Janus.JanusException {
        if (args.length < 5) {
            throw new UsageException("encrypt needs OUTPUT INPUT RECIPIENTS");
        }
        Path output = Path.of(args[1]);
        refuseExisting(output);
        List<Janus.Face> faces = new ArrayList<>();
        int i = 2;
        while (i < args.length) {
            if (!faces.isEmpty()) {
                if (!args[i].equals("--hidden")) {
                    throw new UsageException("unexpected argument: " + args[i]);
                }
                i++;
                if (i >= args.length) {
                    throw new UsageException("--hidden needs INPUT RECIPIENTS");
                }
            }
            byte[] plaintext = Files.readAllBytes(Path.of(args[i++]));
            byte[] password = null;
            List<byte[]> keys = new ArrayList<>();
            int passwords = 0;
            while (i < args.length && !args[i].equals("--hidden")) {
                String opt = args[i];
                if (i + 1 >= args.length) {
                    throw new UsageException(opt + " needs a value");
                }
                String value = args[i + 1];
                switch (opt) {
                    case "--pass" -> {
                        password = value.getBytes(StandardCharsets.UTF_8);
                        passwords++;
                    }
                    case "--to" -> keys.add(Keys.decodePublicKey(value));
                    case "--to-file" -> keys.addAll(Keys.readPublicKeyFile(Path.of(value)));
                    default -> throw new UsageException("unexpected argument: " + opt);
                }
                i += 2;
            }
            if (passwords > 1 || (password != null && !keys.isEmpty())) {
                throw Janus.JanusException.rule("a password face has exactly one recipient, its password (R1)");
            }
            if (password == null && keys.isEmpty()) {
                throw new UsageException("a face needs recipients");
            }
            faces.add(password != null ? Janus.Face.withPassword(plaintext, password)
                                       : Janus.Face.withKeys(plaintext, keys));
        }
        byte[] file = Janus.encrypt(faces.get(0), faces.subList(1, faces.size()), new SecureRandom());
        writeNew(output, file);
    }

    private static void decrypt(String[] args) throws UsageException, IOException, Janus.JanusException {
        if (args.length < 5) {
            throw new UsageException("decrypt needs INPUT OUTPUT and credentials");
        }
        Path input = Path.of(args[1]);
        Path output = Path.of(args[2]);
        refuseExisting(output);
        byte[] password = null;
        List<Path> ids = new ArrayList<>();
        for (int i = 3; i < args.length; i += 2) {
            if (i + 1 >= args.length) {
                throw new UsageException(args[i] + " needs a value");
            }
            switch (args[i]) {
                case "--pass" -> {
                    if (password != null) {
                        throw new UsageException("one password only");
                    }
                    password = args[i + 1].getBytes(StandardCharsets.UTF_8);
                }
                case "--id" -> ids.add(Path.of(args[i + 1]));
                default -> throw new UsageException("unexpected argument: " + args[i]);
            }
        }
        if ((password == null) == ids.isEmpty()) {
            throw new UsageException("give either --pass or --id");
        }
        byte[] file;
        try {
            file = Files.readAllBytes(input);
        } catch (IOException e) {
            throw Janus.JanusException.cannotDecrypt();
        }
        byte[] plain;
        if (password != null) {
            plain = Janus.decryptWithPassword(file, password);
            Arrays.fill(password, (byte) 0);
        } else {
            List<XWing.KeyPair> identities = new ArrayList<>();
            for (Path p : ids) {
                byte[] seed = Keys.readIdentityFile(p);
                identities.add(new XWing.KeyPair(seed));
                Arrays.fill(seed, (byte) 0);
            }
            try {
                plain = Janus.decryptWithIdentities(file, identities);
            } finally {
                identities.forEach(XWing.KeyPair::wipe);
            }
        }
        try {
            writeNew(output, plain);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    /** Output files are never overwritten (clients/README.md). */
    private static void refuseExisting(Path output) throws IOException {
        if (Files.exists(output, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException(output + " already exists; not overwriting it");
        }
    }

    private static void writeNew(Path output, byte[] data) throws IOException {
        try {
            Files.write(output, data, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } catch (java.nio.file.FileAlreadyExistsException e) {
            throw new IOException(output + " already exists; not overwriting it");
        }
    }
}
