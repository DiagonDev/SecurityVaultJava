package com.etbasic.securityvault.core.cipher;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implementazione di AeadCipher basata su AES-GCM.
 *
 * Output di encrypt:
 *   IV (nonce) || CIPHERTEXT || TAG
 *
 * IV (nonce) serve per rendere la cifratura non deterministica:
 * deve essere unico (o almeno non riutilizzato) ma non è segreto.
 */
public class AesGcmCipher implements AeadCipher {

    // 96 bit, raccomandato per GCM
    private final int ivSizeBytes;

    // 128 bit
    private final int tagSizeBytes;

    private final SecureRandom rng;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ALGORITHM = "AES";

    /**
     * Costruttore di default:
     * IV = 12 byte, TAG = 16 byte, SecureRandom di default.
     */
    public AesGcmCipher() {
        this(12, 16, new SecureRandom());
    }

    /**
     * Costruttore personalizzato.
     *
     * @param ivSizeBytes  dimensione IV in byte (es. 12)
     * @param tagSizeBytes dimensione TAG in byte (es. 16)
     * @param rng          sorgente di random
     */
    public AesGcmCipher(int ivSizeBytes, int tagSizeBytes, SecureRandom rng) {
        this.ivSizeBytes = ivSizeBytes;
        this.tagSizeBytes = tagSizeBytes;
        this.rng = (rng != null) ? rng : new SecureRandom();
    }

    @Override
    public byte[] encrypt(byte[] key, byte[] plaintext, byte[] aad) {
        // Controllo dimensione chiave: 128 / 192 / 256 bit
        if (key == null || !(key.length == 16 || key.length == 24 || key.length == 32)) {
            throw new IllegalArgumentException("AES key must be 16, 24, or 32 bytes");
        }

        if (plaintext == null) {
            plaintext = new byte[0]; // GCM supporta plaintext di lunghezza 0
        }

        // Genera IV/nonce casuale (12 byte raccomandati per GCM)
        byte[] iv = new byte[ivSizeBytes];
        rng.nextBytes(iv);

        try {
            // Prepara chiave e parametri GCM (tag a 128 bit = 16 byte)
            SecretKeySpec sk = new SecretKeySpec(key, ALGORITHM);          // "AES"
            GCMParameterSpec gcmSpec = new GCMParameterSpec(tagSizeBytes * 8, iv);

            // Inizializza il Cipher in ENCRYPT_MODE con AES/GCM/NoPadding
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);            // "AES/GCM/NoPadding"
            cipher.init(Cipher.ENCRYPT_MODE, sk, gcmSpec);

            // (Opzionale) Collega AAD prima dei dati: autenticata ma non cifrata
            if (aad != null) {
                cipher.updateAAD(aad);
            }

            // Cifra e calcola il TAG in un colpo solo:
            // doFinal() ritorna: ciphertext || tag (tag in coda)
            byte[] ctPlusTag = cipher.doFinal(plaintext);

            // Componi l’output nel layout: IV || (ciphertext || tag)
            byte[] out = new byte[iv.length + ctPlusTag.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ctPlusTag, 0, out, iv.length, ctPlusTag.length);

            // Ritorna il blob completo pronto da salvare nel file vault
            return out;
        } catch (Exception e) {
            // Qualsiasi eccezione crittografica la wrappiamo in una RuntimeException (oppure puoi
            // scegliere una tua eccezione checked/unchecked a livello di progetto)
            throw new RuntimeException("Encryption failed", e);
        } finally {
            // Azzera IV temporaneo (buona pratica)
            zeroize(iv);
        }
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] ciphertextWithIv, byte[] aad)
            throws AEADBadTagException, IllegalArgumentException {

        if (key == null || !(key.length == 16 || key.length == 24 || key.length == 32)) {
            throw new IllegalArgumentException("AES key must be 16, 24, or 32 bytes");
        }

        if (ciphertextWithIv == null ||
                ciphertextWithIv.length < ivSizeBytes + tagSizeBytes) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        // Parsing del blob: estrai IV e il blocco 'ciphertext||tag'
        byte[] iv = Arrays.copyOfRange(ciphertextWithIv, 0, ivSizeBytes);
        byte[] ctPlusTag = Arrays.copyOfRange(ciphertextWithIv, ivSizeBytes, ciphertextWithIv.length);

        try {
            // Prepara chiave e parametri GCM con lo stesso IV
            SecretKeySpec sk = new SecretKeySpec(key, ALGORITHM);          // "AES"
            GCMParameterSpec gcm = new GCMParameterSpec(tagSizeBytes * 8, iv); // tag 128 bit

            // Inizializza cipher in DECRYPT_MODE e ri-applica l'AAD identica alla cifratura
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);            // "AES/GCM/NoPadding"
            cipher.init(Cipher.DECRYPT_MODE, sk, gcm);

            if (aad != null) {
                cipher.updateAAD(aad);
            }

            // Verifica il TAG e, se valido, restituisce il plaintext
            // Se key/IV/AAD o i dati sono errati/manomessi → AEADBadTagException
            return cipher.doFinal(ctPlusTag);
        } catch (AEADBadTagException e) {
            // La rilanciamo così come dichiarato in firma
            throw e;
        } catch (IllegalArgumentException e) {
            // La rilanciamo per coerenza con la documentazione
            throw e;
        } catch (Exception e) {
            // Qualsiasi altra eccezione crittografica → RuntimeException (o tua eccezione personalizzata)
            throw new RuntimeException("Decryption failed", e);
        } finally {
            // Azzera temporanei
            zeroize(iv);
            zeroize(ctPlusTag);
        }
    }

    /**
     * Azzera in-place il contenuto dell'array (best practice per dati sensibili).
     */
    private void zeroize(byte[] arr) {
        if (arr == null) return;
        Arrays.fill(arr, (byte) 0);
    }
}
