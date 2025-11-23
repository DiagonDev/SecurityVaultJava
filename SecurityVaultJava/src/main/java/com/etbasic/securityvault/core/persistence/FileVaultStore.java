package com.etbasic.securityvault.core.persistence;

import com.etbasic.securityvault.core.model.VaultHeader;
import com.etbasic.securityvault.core.model.VaultHeaderCodec;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;

/**
 * Semplice FileVaultStore didattico.
 * Formato del file sul disco: [4 byte BE headerLen] [headerJsonBytes] [ciphertext||tag (blob)]
 *
 * Questa classe espone funzioni minimali: write, read, delete, exists.
 * È pensata per essere semplice e leggibile, non per produzione.
 */
public class FileVaultStore implements VaultStore {

    private final File dir;

    public FileVaultStore(File dir) {
        this.dir = dir;
        if (!dir.exists()) {
            dir.mkdirs();
        }
        if (!dir.isDirectory()) {
            throw new IllegalArgumentException("Provided path is not a directory: " + dir.getPath());
        }
    }

    public static class VaultFile {
        private final VaultHeader header;
        private final byte[] ciphertext;

        public VaultFile(VaultHeader header, byte[] ciphertext) {
            this.header = header;
            this.ciphertext = ciphertext;
        }

        public VaultHeader getHeader() {
            return header;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }
    }

    /**
     * Scrive atomicamente il file vault. Se il file già esiste viene sovrascritto.
     */
    @Override
    public void write(String filename, VaultHeader header, byte[] ciphertext) throws IOException {
        byte[] headerBytes = VaultHeaderCodec.toJsonBytes(header);
        int headerLen = headerBytes.length;

        ByteBuffer out = ByteBuffer
                .allocate(4 + headerLen + ciphertext.length)
                .order(ByteOrder.BIG_ENDIAN);

        out.putInt(headerLen);
        out.put(headerBytes);
        out.put(ciphertext);
        byte[] bytes = out.array();

        Path target = dir.toPath().resolve(filename);

        // Write to temp file then atomically move
        Path tmp = Files.createTempFile(dir.toPath(), "vault", ".tmp");
        try {
            Files.write(tmp, bytes);
            try {
                Files.move(tmp, target,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception e) {
                // Se ATOMIC_MOVE non è supportato, esegui rename non-atomico come fallback
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            // cerca di eliminare il tmp se esiste ancora
            try {
                Files.deleteIfExists(tmp);
            } catch (Exception ignored) {
            }
            // azzera l'array temporaneo per buona pratica
            Arrays.fill(bytes, (byte) 0);
            Arrays.fill(headerBytes, (byte) 0);
        }
    }

    /**
     * Legge il file e restituisce header + ciphertext.
     * Lancia IOException se il file non esiste
     * o IllegalArgumentException se il file è malformato.
     */
    @Override
    public VaultFile read(String filename) throws IOException, IllegalArgumentException {
        Path target = dir.toPath().resolve(filename);
        byte[] all = Files.readAllBytes(target);

        if (all.length < 4) {
            throw new IllegalArgumentException("File troppo corto per contenere la lunghezza dell'header");
        }

        ByteBuffer bb = ByteBuffer.wrap(all).order(ByteOrder.BIG_ENDIAN);
        int headerLen = bb.getInt();
        if (headerLen <= 0 || headerLen > all.length - 4) {
            throw new IllegalArgumentException("Header length non valida: " + headerLen);
        }

        byte[] headerBytes = new byte[headerLen];
        bb.get(headerBytes);

        byte[] cipherBytes = new byte[bb.remaining()];
        bb.get(cipherBytes);

        VaultHeader header = VaultHeaderCodec.fromJsonBytes(headerBytes);

        // azzera i buffer temporanei non necessari
        Arrays.fill(headerBytes, (byte) 0);

        // (non azzeriamo `all` per gli stessi motivi del commento Kotlin)
        return new VaultFile(header, cipherBytes);
    }

    @Override
    public boolean exists(String filename) {
        return Files.exists(dir.toPath().resolve(filename));
    }

    @Override
    public boolean delete(String filename) throws IOException {
        return Files.deleteIfExists(dir.toPath().resolve(filename));
    }
}
