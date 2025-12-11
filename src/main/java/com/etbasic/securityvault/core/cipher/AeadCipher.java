package com.etbasic.securityvault.core.cipher;

import javax.crypto.AEADBadTagException;

/**
 * Cifrario AEAD (Authenticated Encryption with Associated Data).
 *
 * IV (nonce) || CIPHERTEXT (testo cifrato) || TAG (codice di autenticazione)
 *
 * IV serve per rendere la cifratura non deterministica cambiando sempre, altrimenti un attaccante capirebbe
 * che il testo cifrato non è cambiato anche senza password. Non deve essere segreto.
 * "blob" è un insieme di dati, nel nostro caso: IV | cipherText | TAG.
 */
public interface AeadCipher {

    /**
     * @param key       chiave derivata fornita da KDF
     * @param plaintext byte in chiaro che vogliamo mettere nel vault (es. file con passwords)
     * @param aad       dati non cifrati, usati per impedire manomissioni (entra nel calcolo del TAG).
     *                  Può essere {@code null}.
     * @return byte[] contenente: IV (nonce) || CIPHERTEXT || TAG
     */
    byte[] encrypt(byte[] key, byte[] plaintext, byte[] aad);

    /**
     * @param key                la stessa chiave derivata usata in cifratura
     * @param ciphertextWithIv   blob completo nel formato: IV || CIPHERTEXT || TAG
     * @param aad                gli stessi dati AAD usati in cifratura; se differiscono la verifica fallisce.
     *                           Può essere {@code null}.
     * @return il plaintext originale in chiaro
     * @throws AEADBadTagException     se il TAG non è valido (chiave/IV/AAD errati o dati manomessi)
     * @throws IllegalArgumentException se gli input non sono nel formato atteso (es. blob troppo corto)
     */
    byte[] decrypt(byte[] key, byte[] ciphertextWithIv, byte[] aad) throws AEADBadTagException, IllegalArgumentException;
}
