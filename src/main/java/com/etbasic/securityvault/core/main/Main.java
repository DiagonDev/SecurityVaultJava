package com.etbasic.securityvault.core.main;

import com.etbasic.securityvault.core.cipher.AesGcmCipher;
import com.etbasic.securityvault.core.kdf.PBKDF2;
import com.etbasic.securityvault.core.model.VaultEntry;
import com.etbasic.securityvault.core.model.VaultHeader;
import com.etbasic.securityvault.core.model.VaultHeaderCodec;
import com.etbasic.securityvault.core.model.VaultPayload;
import com.etbasic.securityvault.core.persistence.FileVaultStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import javax.crypto.AEADBadTagException;
import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {

    // Json pretty-print con Jackson (equivalente a Json { prettyPrint = true; encodeDefaults = true })
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    // Per la lettura da stdin (equivalente a readLine())
    private static final BufferedReader STDIN_READER =
            new BufferedReader(new InputStreamReader(System.in));

    public static void main(String[] args) {
        // directory locale dove salvare i vault (per semplicità)
        File vaultDir = new File("vaults");
        FileVaultStore store = new FileVaultStore(vaultDir);

        System.out.println("Simple SecurityVault — demo CLI");

        boolean running = true;
        while (running) {
            System.out.println();
            System.out.println("Scegli: (1) crea  (2) apri  (3) aggiungi  (4) cambia-pw  (5) cancella  (q) esci");
            String choice = readLineTrim();
            switch (choice) {
                case "1":
                    createVaultFlow(store);
                    break;
                case "2":
                    openVaultFlow(store);
                    break;
                case "3":
                    addEntryFlow(store);
                    break;
                case "4":
                    changePasswordFlow(store);
                    break;
                case "5":
                    deleteFlow(store);
                    break;
                case "q":
                case "Q":
                    running = false;
                    break;
                default:
                    System.out.println("scelta non valida");
            }
        }
        System.out.println("bye");
    }

    // ---------- utility per input password (Console se disponibile, altrimenti stdin) ----------

    private static char[] readPassword(String prompt) {
        Console cons = System.console();
        if (cons != null) {
            return cons.readPassword(prompt);
        } else {
            // fallback (IDE): legge come stringa (meno sicuro perché visibile)
            System.out.print(prompt);
            String line = readLine();
            if (line == null) line = "";
            return line.toCharArray();
        }
    }

    private static String readLineTrim() {
        String line = readLine();
        return line == null ? "" : line.trim();
    }

    private static String readLine() {
        try {
            return STDIN_READER.readLine();
        } catch (IOException e) {
            return null;
        }
    }

    // ---------- Flusso: creare un nuovo vault ----------

    private static void createVaultFlow(FileVaultStore store) {
        System.out.print("Nome file vault (es. myvault.dat): ");
        String filename = readLineTrim();
        if (filename.isEmpty()) {
            System.out.println("Nome richiesto");
            return;
        }

        char[] pwChars = readPassword("Scegli una master password: ");
        String pw = new String(pwChars);
        Arrays.fill(pwChars, '\u0000'); // zeroizza il char[] originale per buona pratica

        // parametri (didattici) — puoi adattarli alla policy della tua app
        int encIterations = 65536;
        int keyLenBytes = 32; // AES-256

        // 1) stored auth hash (usato per verificare la password senza decifrare)
        PBKDF2 authKdf = new PBKDF2(); // usa default (stesso usato in validatePassword)
        String storedAuthHash = authKdf.hashPassword(pw);

        // 2) enc salt e derivazione chiave
        byte[] encSalt = new byte[16];
        new SecureRandom().nextBytes(encSalt);
        PBKDF2 encKdf = new PBKDF2(encIterations, keyLenBytes * 8);
        byte[] encKey = encKdf.deriveKey(pw, encSalt);

        // 3) crea header
        VaultHeader header = new VaultHeader(
                encSalt,
                encIterations,
                keyLenBytes,
                storedAuthHash,
                "sha256(header-json)"
        );

        // 4) plaintext iniziale (vuoto)
        VaultPayload initialData = new VaultPayload();
        byte[] plaintext;
        try {
            plaintext = objectMapper
                    .writeValueAsString(initialData)
                    .getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.out.println("Errore serializzazione iniziale: " + e.getMessage());
            Arrays.fill(encKey, (byte) 0);
            return;
        }

        // 5) AAD = sha256(header-json)
        byte[] aad = VaultHeaderCodec.aadOf(header);

        // 6) cifra e salva (atomicamente)
        AesGcmCipher cipher = new AesGcmCipher();
        byte[] blob = cipher.encrypt(encKey, plaintext, aad);
        try {
            store.write(filename, header, blob);
            System.out.println("Vault creato: " + store.exists(filename) + " (" + filename + ")");
        } catch (Exception e) {
            System.out.println("Errore scrittura vault: " + e.getMessage());
        } finally {
            // azzera key e plaintext in memoria
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    // ---------- Flusso: aprire/unlock il vault e mostrare entries ----------

    private static void openVaultFlow(FileVaultStore store) {
        System.out.print("Nome file vault da aprire: ");
        String filename = readLineTrim();
        if (!store.exists(filename)) {
            System.out.println("File non trovato");
            return;
        }

        char[] pwChars = readPassword("Inserisci la master password: ");
        String pw = new String(pwChars);
        Arrays.fill(pwChars, '\u0000');

        try {
            var vf = store.read(filename);
            VaultHeader header = vf.getHeader();

            // verifica password (auth)
            PBKDF2 authKdf = new PBKDF2();
            if (!authKdf.validatePassword(header.getStoredAuthHash(), pw)) {
                System.out.println("Password errata");
                return;
            }

            PBKDF2 encKdf = new PBKDF2(header.getEncIterations(), header.getKeyLenBytes() * 8);
            byte[] encKey = encKdf.deriveKey(pw, header.getEncSalt());
            byte[] aad = VaultHeaderCodec.aadOf(header);

            byte[] plain = new AesGcmCipher().decrypt(encKey, vf.getCiphertext(), aad);

            VaultPayload vaultData = objectMapper.readValue(
                    plain,
                    VaultPayload.class
            );

            System.out.println("=== Entries (" + vaultData.getEntries().size() + ") ===");
            for (int i = 0; i < vaultData.getEntries().size(); i++) {
                VaultEntry e = vaultData.getEntries().get(i);
                String notes = (e.getNotes() != null) ? e.getNotes() : "-";
                System.out.println((i + 1) + ") " + e.getTitle()
                        + "  [" + e.getUsername() + "] -> " + e.getPassword()
                        + "  notes:" + notes);
            }

            // pulizia memoria
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(plain, (byte) 0);
        } catch (AEADBadTagException e) {
            System.out.println("Decrittazione fallita (chiave/AAD errata o dati corrotti).");
        } catch (Exception e) {
            System.out.println("Errore aprendo il vault: " + e.getMessage());
        }
    }

    // ---------- Flusso: aggiungere una entry (legge -> modifica -> riscrive) ----------

    private static void addEntryFlow(FileVaultStore store) {
        System.out.print("Vault filename: ");
        String filename = readLineTrim();
        if (!store.exists(filename)) {
            System.out.println("File non trovato");
            return;
        }

        char[] pwChars = readPassword("Inserisci master password: ");
        String pw = new String(pwChars);
        Arrays.fill(pwChars, '\u0000');

        try {
            var vf = store.read(filename);
            VaultHeader header = vf.getHeader();

            // auth
            PBKDF2 authKdf = new PBKDF2();
            if (!authKdf.validatePassword(header.getStoredAuthHash(), pw)) {
                System.out.println("Password errata");
                return;
            }

            PBKDF2 encKdf = new PBKDF2(header.getEncIterations(), header.getKeyLenBytes() * 8);
            byte[] encKey = encKdf.deriveKey(pw, header.getEncSalt());
            byte[] aad = VaultHeaderCodec.aadOf(header);

            byte[] plain = new AesGcmCipher().decrypt(encKey, vf.getCiphertext(), aad);

            VaultPayload vaultData = objectMapper.readValue(
                    plain,
                    VaultPayload.class
            );

            // input nuova entry
            System.out.print("Titolo: ");
            String title = readLineTrim();
            System.out.print("Username: ");
            String username = readLineTrim();
            char[] passwordChars = readPassword("Password entry: ");
            String entryPw = new String(passwordChars);
            Arrays.fill(passwordChars, '\u0000');
            System.out.print("Notes (opzionale): ");
            String notes = readLine();

            String id = String.valueOf(System.currentTimeMillis());
            VaultEntry entry = new VaultEntry(id, title, username, entryPw, notes);
            vaultData.getEntries().add(entry);

            // serializza, cifra e riscrivi con stesso header
            byte[] newPlain = objectMapper
                    .writeValueAsString(vaultData)
                    .getBytes(StandardCharsets.UTF_8);

            byte[] newBlob = new AesGcmCipher().encrypt(encKey, newPlain, aad);
            store.write(filename, header, newBlob);
            System.out.println("Entry aggiunta.");

            // pulizie
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(plain, (byte) 0);
            Arrays.fill(newPlain, (byte) 0);
        } catch (Exception e) {
            System.out.println("Errore: " + e.getMessage());
        }
    }

    // ---------- Flusso: cambiare password master ----------

    private static void changePasswordFlow(FileVaultStore store) {
        System.out.print("Vault filename: ");
        String filename = readLineTrim();
        if (!store.exists(filename)) {
            System.out.println("File non trovato");
            return;
        }

        char[] oldPwChars = readPassword("Vecchia master password: ");
        String oldPw = new String(oldPwChars);
        Arrays.fill(oldPwChars, '\u0000');

        char[] newPwChars = readPassword("Nuova master password: ");
        String newPw = new String(newPwChars);
        Arrays.fill(newPwChars, '\u0000');

        try {
            var vf = store.read(filename);
            VaultHeader header = vf.getHeader();

            // auth vecchia
            PBKDF2 authKdf = new PBKDF2();
            if (!authKdf.validatePassword(header.getStoredAuthHash(), oldPw)) {
                System.out.println("Vecchia password errata");
                return;
            }

            // decifra con chiave derivata dalla vecchia pw
            PBKDF2 encKdfOld = new PBKDF2(header.getEncIterations(), header.getKeyLenBytes() * 8);
            byte[] oldKey = encKdfOld.deriveKey(oldPw, header.getEncSalt());
            byte[] aadOld = VaultHeaderCodec.aadOf(header);
            byte[] plaintext = new AesGcmCipher().decrypt(oldKey, vf.getCiphertext(), aadOld);

            VaultPayload vaultData = objectMapper.readValue(
                    plaintext,
                    VaultPayload.class
            );

            // ora rigenera header + key con la nuova password
            byte[] newEncSalt = new byte[16];
            new SecureRandom().nextBytes(newEncSalt);
            int newEncIterations = header.getEncIterations(); // puoi cambiarlo se vuoi
            int newKeyLen = header.getKeyLenBytes();
            PBKDF2 encKdfNew = new PBKDF2(newEncIterations, newKeyLen * 8);
            byte[] newKey = encKdfNew.deriveKey(newPw, newEncSalt);
            String newStoredAuth = new PBKDF2().hashPassword(newPw);

            // equivalente di header.copy(encSalt=..., encIterations=..., storedAuthHash=...)
            VaultHeader newHeader = new VaultHeader(
                    newEncSalt,
                    newEncIterations,
                    newKeyLen,
                    newStoredAuth,
                    header.getAadFormat()
            );

            byte[] newAad = VaultHeaderCodec.aadOf(newHeader);
            byte[] newPlain = objectMapper
                    .writeValueAsString(vaultData)
                    .getBytes(StandardCharsets.UTF_8);
            byte[] newBlob = new AesGcmCipher().encrypt(newKey, newPlain, newAad);

            store.write(filename, newHeader, newBlob);
            System.out.println("Master password aggiornata.");

            // pulizie
            Arrays.fill(oldKey, (byte) 0);
            Arrays.fill(newKey, (byte) 0);
            Arrays.fill(plaintext, (byte) 0);
            Arrays.fill(newPlain, (byte) 0);

        } catch (Exception e) {
            System.out.println("Errore cambio password: " + e.getMessage());
        }
    }

    // ---------- Flusso: cancellare file vault ----------

    private static void deleteFlow(FileVaultStore store) {
        System.out.print("Vault filename da cancellare: ");
        String filename = readLineTrim();
        if (!store.exists(filename)) {
            System.out.println("File non trovato");
            return;
        }
        System.out.print("Sei sicuro? (y/N): ");
        if (!"y".equalsIgnoreCase(readLineTrim())) {
            System.out.println("annullato");
            return;
        }
        try {
            boolean ok = store.delete(filename);
            System.out.println("Cancellato: " + ok);
        } catch (Exception e) {
            System.out.println("Errore cancellazione: " + e.getMessage());
        }
    }
}
