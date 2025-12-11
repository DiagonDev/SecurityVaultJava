package com.etbasic.securityvault.core.kdf;

/**
 * Interfaccia per funzioni di derivazione di chiave (KDF).
 */
public interface KDF {

    /**
     * Calcola e ritorna una stringa pronta per la memorizzazione che rappresenta
     * il risultato dell'hashing della password.
     *
     * @param password la password in chiaro da derivare
     * @return una stringa contenente il salt e l'hash, per la memorizzazione nel DB
     */
    String hashPassword(String password);

    /**
     * Verifica se la password fornita corrisponde all'hash memorizzato.
     *
     * @param storedHash    la stringa salvata nel DB
     * @param inputPassword la password fornita dall'utente per il login
     * @return true se la password è corretta
     */
    boolean validatePassword(String storedHash, String inputPassword);

    /**
     * Crea la chiave derivata da utilizzare per cifrare i dati con AES.
     *
     * @param password la password inserita dall'utente
     * @param salt     il salt utilizzato per quella password
     * @return la chiave derivata (byte[])
     */
    byte[] deriveKey(String password, byte[] salt);
}
