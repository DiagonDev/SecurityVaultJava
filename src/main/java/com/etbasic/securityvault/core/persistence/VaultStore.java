package com.etbasic.securityvault.core.persistence;

import com.etbasic.securityvault.core.model.VaultHeader;
import com.etbasic.securityvault.core.persistence.FileVaultStore.VaultFile;

import java.io.IOException;

public interface VaultStore {

    /**
     * Salva il blob del vault (nonce + ciphertext + tag) in modo atomico.
     */
    void write(String filename, VaultHeader header, byte[] ciphertext) throws IOException;

    /**
     * Carica e ritorna il blob completo.
     * Lancia eccezione se il file non esiste o è malformato.
     */
    VaultFile read(String filename) throws IOException;

    /**
     * Controlla se il vault esiste.
     */
    boolean exists(String filename);

    /**
     * Rimuove il file del vault.
     */
    boolean delete(String filename) throws IOException;
}
