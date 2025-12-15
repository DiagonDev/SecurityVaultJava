package com.etbasic.securityvault.core.main;

import com.etbasic.securityvault.core.cipher.AesGcmCipher;
import com.etbasic.securityvault.core.kdf.PBKDF2;
import com.etbasic.securityvault.core.model.VaultEntry;
import com.etbasic.securityvault.core.model.VaultHeader;
import com.etbasic.securityvault.core.model.VaultHeaderCodec;
import com.etbasic.securityvault.core.model.VaultPayload;
import com.etbasic.securityvault.core.persistence.FileVaultStore;
import com.etbasic.securityvault.core.utils.Colors;
import com.etbasic.securityvault.core.utils.VerticalMenu;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import javax.crypto.AEADBadTagException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

public class Main {

    private static final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public static void main(String[] args) {
        File vaultDir = new File("vaults");
        FileVaultStore store = new FileVaultStore(vaultDir);

        try {
            Terminal terminal = TerminalBuilder.builder()
                    .name("Custom Terminal")
                    .system(true)
                    .dumb(false)
                    .jna(true)
                    .color(true)
                    .encoding("UTF-8")
                    .build();

            terminal.enterRawMode();

            LineReader reader = LineReaderBuilder.builder()
                    .terminal(terminal)
                    .build();

            terminal.writer().println(Colors.get("yellow") + "SecurityVault - demo CLI" + Colors.get("reset"));
            terminal.flush();

            // lista del menu
            List<VerticalMenu.MenuItem> menuItems = List.of(
                    new VerticalMenu.MenuItem("Crea vault", () -> createVaultFlow(store, terminal, reader)),
                    new VerticalMenu.MenuItem("Apri vault", () -> openVaultFlow(store, terminal, reader)),
                    new VerticalMenu.MenuItem("Aggiungi entry", () -> addEntryFlow(store, terminal, reader)),
                    new VerticalMenu.MenuItem("Cambia password", () -> changePasswordFlow(store, terminal, reader)),
                    new VerticalMenu.MenuItem("Cancella vault", () -> deleteFlow(store, terminal, reader)),
                    new VerticalMenu.MenuItem("Esci", () -> System.exit(0))
            );

            new VerticalMenu(terminal, menuItems).show();



            terminal.writer().println(Colors.get("green") + "Bye!" + Colors.get("reset"));
            terminal.flush();

        } catch (IOException e) {
            System.err.println("Error creating terminal: " + e.getMessage());
        }
    }

    // ---------- Utility per input ----------

    private static char[] readPassword(LineReader reader, String prompt) {
        String pw = reader.readLine(Colors.get("magenta") + prompt + Colors.get("reset"), '*');
        return pw.toCharArray();
    }

    // ---------- Flussi aggiornati ----------

    private static void createVaultFlow(FileVaultStore store, Terminal terminal, LineReader reader) {
        terminal.writer().print(Colors.get("cyan") + "Nome file vault (es. password.dat): " + Colors.get("reset"));
        terminal.flush();
        String filename = reader.readLine("").trim();

        if (filename.isEmpty()) {
            terminal.writer().println(Colors.get("red") + "Nome richiesto" + Colors.get("reset"));
            terminal.flush();
            return;
        }

        char[] pwChars = readPassword(reader, "Scegli una master password: ");
        String pw = new String(pwChars);
        Arrays.fill(pwChars, '\u0000');

        int encIterations = 65536;
        int keyLenBytes = 32;

        PBKDF2 authKdf = new PBKDF2();
        String storedAuthHash = authKdf.hashPassword(pw);

        byte[] encSalt = new byte[16];
        new SecureRandom().nextBytes(encSalt);
        PBKDF2 encKdf = new PBKDF2(encIterations, keyLenBytes * 8);
        byte[] encKey = encKdf.deriveKey(pw, encSalt);

        VaultHeader header = new VaultHeader(encSalt, encIterations, keyLenBytes, storedAuthHash, "sha256(header-json)");

        VaultPayload initialData = new VaultPayload();
        byte[] plaintext;
        try {
            plaintext = objectMapper.writeValueAsString(initialData).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            terminal.writer().println(Colors.get("red") + "Errore serializzazione iniziale: " + e.getMessage() + Colors.get("reset"));
            terminal.flush();
            Arrays.fill(encKey, (byte) 0);
            return;
        }

        byte[] aad = VaultHeaderCodec.aadOf(header);

        AesGcmCipher cipher = new AesGcmCipher();
        byte[] blob = cipher.encrypt(encKey, plaintext, aad);
        try {
            store.write(filename, header, blob);
            terminal.writer().println(Colors.get("green") + "Vault creato: " + store.exists(filename) + " (" + filename + ")" + Colors.get("reset"));
            terminal.flush();
        } catch (Exception e) {
            terminal.writer().println(Colors.get("red") + "Errore scrittura vault: " + e.getMessage() + Colors.get("reset"));
            terminal.flush();
        } finally {
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static void openVaultFlow(FileVaultStore store, Terminal terminal, LineReader reader) {
        terminal.writer().print(Colors.get("cyan") + "Nome file vault da aprire: " + Colors.get("reset"));
        terminal.flush();
        String filename = reader.readLine("").trim();
        if (!store.exists(filename)) {
            terminal.writer().println(Colors.get("red") + "File non trovato" + Colors.get("reset"));
            terminal.flush();
            return;
        }

        char[] pwChars = readPassword(reader, "Inserisci la master password: ");
        String pw = new String(pwChars);
        Arrays.fill(pwChars, '\u0000');

        try {
            var vf = store.read(filename);
            VaultHeader header = vf.getHeader();

            PBKDF2 authKdf = new PBKDF2();
            if (!authKdf.validatePassword(header.getStoredAuthHash(), pw)) {
                terminal.writer().println(Colors.get("red") + "Password errata" + Colors.get("reset"));
                terminal.flush();
                return;
            }

            PBKDF2 encKdf = new PBKDF2(header.getEncIterations(), header.getKeyLenBytes() * 8);
            byte[] encKey = encKdf.deriveKey(pw, header.getEncSalt());
            byte[] aad = VaultHeaderCodec.aadOf(header);

            byte[] plain = new AesGcmCipher().decrypt(encKey, vf.getCiphertext(), aad);

            VaultPayload vaultData = objectMapper.readValue(plain, VaultPayload.class);

            terminal.writer().println(Colors.get("yellow") + "=== Entries (" + vaultData.getEntries().size() + ") ===" + Colors.get("reset"));
            for (int i = 0; i < vaultData.getEntries().size(); i++) {
                VaultEntry e = vaultData.getEntries().get(i);
                String notes = (e.getNotes() != null) ? e.getNotes() : "-";
                terminal.writer().println((i + 1) + ") " + e.getTitle()
                        + "  [" + e.getUsername() + "] -> " + e.getPassword()
                        + "  notes:" + notes);
            }
            terminal.flush();

            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(plain, (byte) 0);
        } catch (AEADBadTagException e) {
            terminal.writer().println(Colors.get("red") + "Decrittazione fallita (chiave/AAD errata o dati corrotti)." + Colors.get("reset"));
            terminal.flush();
        } catch (Exception e) {
            terminal.writer().println(Colors.get("red") + "Errore aprendo il vault: " + e.getMessage() + Colors.get("reset"));
            terminal.flush();
        }
    }

    // ---------- Aggiungi Entry ----------

    private static void addEntryFlow(FileVaultStore store, Terminal terminal, LineReader reader) {
        terminal.writer().print(Colors.get("cyan") + "Vault filename: " + Colors.get("reset"));
        terminal.flush();
        String filename = reader.readLine("").trim();
        if (!store.exists(filename)) {
            terminal.writer().println(Colors.get("red") + "File non trovato" + Colors.get("reset"));
            terminal.flush();
            return;
        }

        char[] pwChars = readPassword(reader, "Inserisci master password: ");
        String pw = new String(pwChars);
        Arrays.fill(pwChars, '\u0000');

        try {
            var vf = store.read(filename);
            VaultHeader header = vf.getHeader();

            PBKDF2 authKdf = new PBKDF2();
            if (!authKdf.validatePassword(header.getStoredAuthHash(), pw)) {
                terminal.writer().println(Colors.get("red") + "Password errata" + Colors.get("reset"));
                terminal.flush();
                return;
            }

            PBKDF2 encKdf = new PBKDF2(header.getEncIterations(), header.getKeyLenBytes() * 8);
            byte[] encKey = encKdf.deriveKey(pw, header.getEncSalt());
            byte[] aad = VaultHeaderCodec.aadOf(header);

            byte[] plain = new AesGcmCipher().decrypt(encKey, vf.getCiphertext(), aad);
            VaultPayload vaultData = objectMapper.readValue(plain, VaultPayload.class);

            terminal.writer().print("Titolo: "); terminal.flush();
            String title = reader.readLine("").trim();
            terminal.writer().print("Username: "); terminal.flush();
            String username = reader.readLine("").trim();
            char[] passwordChars = readPassword(reader, "Password entry: ");
            String entryPw = new String(passwordChars);
            Arrays.fill(passwordChars, '\u0000');
            terminal.writer().print("Notes (opzionale): "); terminal.flush();
            String notes = reader.readLine("");

            String id = String.valueOf(System.currentTimeMillis());
            VaultEntry entry = new VaultEntry(id, title, username, entryPw, notes);
            vaultData.getEntries().add(entry);

            byte[] newPlain = objectMapper.writeValueAsString(vaultData).getBytes(StandardCharsets.UTF_8);
            byte[] newBlob = new AesGcmCipher().encrypt(encKey, newPlain, aad);
            store.write(filename, header, newBlob);

            terminal.writer().println(Colors.get("green") + "Entry aggiunta." + Colors.get("reset"));
            terminal.flush();

            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(plain, (byte) 0);
            Arrays.fill(newPlain, (byte) 0);

        } catch (Exception e) {
            terminal.writer().println(Colors.get("red") + "Errore: " + e.getMessage() + Colors.get("reset"));
            terminal.flush();
        }
    }

    // ---------- Cambia password master ----------

    private static void changePasswordFlow(FileVaultStore store, Terminal terminal, LineReader reader) {
        terminal.writer().print("Vault filename: "); terminal.flush();
        String filename = reader.readLine("").trim();
        if (!store.exists(filename)) {
            terminal.writer().println(Colors.get("red") + "File non trovato" + Colors.get("reset"));
            terminal.flush();
            return;
        }

        char[] oldPwChars = readPassword(reader, "Vecchia master password: ");
        String oldPw = new String(oldPwChars);
        Arrays.fill(oldPwChars, '\u0000');

        char[] newPwChars = readPassword(reader, "Nuova master password: ");
        String newPw = new String(newPwChars);
        Arrays.fill(newPwChars, '\u0000');

        try {
            var vf = store.read(filename);
            VaultHeader header = vf.getHeader();

            PBKDF2 authKdf = new PBKDF2();
            if (!authKdf.validatePassword(header.getStoredAuthHash(), oldPw)) {
                terminal.writer().println(Colors.get("red") + "Vecchia password errata" + Colors.get("reset"));
                terminal.flush();
                return;
            }

            PBKDF2 encKdfOld = new PBKDF2(header.getEncIterations(), header.getKeyLenBytes() * 8);
            byte[] oldKey = encKdfOld.deriveKey(oldPw, header.getEncSalt());
            byte[] aadOld = VaultHeaderCodec.aadOf(header);
            byte[] plaintext = new AesGcmCipher().decrypt(oldKey, vf.getCiphertext(), aadOld);

            VaultPayload vaultData = objectMapper.readValue(plaintext, VaultPayload.class);

            byte[] newEncSalt = new byte[16];
            new SecureRandom().nextBytes(newEncSalt);
            int newEncIterations = header.getEncIterations();
            int newKeyLen = header.getKeyLenBytes();
            PBKDF2 encKdfNew = new PBKDF2(newEncIterations, newKeyLen * 8);
            byte[] newKey = encKdfNew.deriveKey(newPw, newEncSalt);
            String newStoredAuth = new PBKDF2().hashPassword(newPw);

            VaultHeader newHeader = new VaultHeader(newEncSalt, newEncIterations, newKeyLen, newStoredAuth, header.getAadFormat());
            byte[] newAad = VaultHeaderCodec.aadOf(newHeader);
            byte[] newPlain = objectMapper.writeValueAsString(vaultData).getBytes(StandardCharsets.UTF_8);
            byte[] newBlob = new AesGcmCipher().encrypt(newKey, newPlain, newAad);

            store.write(filename, newHeader, newBlob);
            terminal.writer().println(Colors.get("green") + "Master password aggiornata." + Colors.get("reset"));
            terminal.flush();

            Arrays.fill(oldKey, (byte) 0);
            Arrays.fill(newKey, (byte) 0);
            Arrays.fill(plaintext, (byte) 0);
            Arrays.fill(newPlain, (byte) 0);

        } catch (Exception e) {
            terminal.writer().println(Colors.get("red") + "Errore cambio password: " + e.getMessage() + Colors.get("reset"));
            terminal.flush();
        }
    }

    // ---------- Cancellazione vault ----------

    private static void deleteFlow(FileVaultStore store, Terminal terminal, LineReader reader) {
        terminal.writer().print("Vault filename da cancellare: "); terminal.flush();
        String filename = reader.readLine("").trim();
        if (!store.exists(filename)) {
            terminal.writer().println(Colors.get("red") + "File non trovato" + Colors.get("reset"));
            terminal.flush();
            return;
        }

        terminal.writer().print("Sei sicuro? (y/N): "); terminal.flush();
        if (!"y".equalsIgnoreCase(reader.readLine("").trim())) {
            terminal.writer().println("Annullato");
            terminal.flush();
            return;
        }

        try {
            boolean ok = store.delete(filename);
            terminal.writer().println(Colors.get("green") + "Cancellato: " + ok + Colors.get("reset"));
            terminal.flush();
        } catch (Exception e) {
            terminal.writer().println(Colors.get("red") + "Errore cancellazione: " + e.getMessage() + Colors.get("reset"));
            terminal.flush();
        }
    }
}
