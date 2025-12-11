package com.etbasic.securityvault.core.kdf;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Implementazione KDF basata su PBKDF2WithHmacSHA256.
 *
 * iterationCount = 65536
 * keyLength      = 256 bit
 *
 * hashPassword:
 *   - genera un salt di 16 byte
 *   - calcola PBKDF2(password, salt, iterationCount, keyLength)
 *   - salva Base64( salt || hash )
 */
public class PBKDF2 implements KDF {

    private static final int SALT_LENGTH_BYTES = 16;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    private final int iterationCount;
    private final int keyLength; // in bit
    private final SecureRandom secureRandom;

    /**
     * Costruttore di default:
     * iterationCount = 65536
     * keyLength      = 256
     */
    public PBKDF2() {
        this(65536, 256);
    }

    /**
     * Costruttore personalizzato.
     *
     * @param iterationCount numero di iterazioni PBKDF2
     * @param keyLength      lunghezza chiave in bit
     */
    public PBKDF2(int iterationCount, int keyLength) {
        this.iterationCount = iterationCount;
        this.keyLength = keyLength;
        this.secureRandom = new SecureRandom();
    }

    @Override
    public String hashPassword(String password) {
        if (password == null) {
            throw new IllegalArgumentException("Password must not be null");
        }

        // Lunghezza del salt in byte, più è lungo => meno rischio di collisioni
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);

        try {
            // Costruisce la specifica per PBKDF2
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);

            // Sceglie l'algoritmo PBKDF2 con HMAC-SHA256
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);

            // encoded restituisce l’array di byte della chiave derivata
            byte[] hash = factory.generateSecret(spec).getEncoded();

            // Concatena salt + hash in un unico array
            byte[] saltPlusHash = new byte[salt.length + hash.length];
            System.arraycopy(salt, 0, saltPlusHash, 0, salt.length);
            System.arraycopy(hash, 0, saltPlusHash, salt.length, hash.length);

            // Codifica salt+hash in Base64 per memorizzazione
            return Base64.getEncoder().encodeToString(saltPlusHash);
        } catch (Exception e) {
            throw new RuntimeException("Error while hashing password", e);
        }
    }

    @Override
    public boolean validatePassword(String storedHash, String inputPassword) {
        if (storedHash == null || inputPassword == null) {
            return false;
        }

        try {
            // Decodifica Base64: otteniamo salt || hash
            byte[] decoded = Base64.getDecoder().decode(storedHash);

            if (decoded.length < SALT_LENGTH_BYTES) {
                return false;
            }

            // I primi 16 byte sono il salt
            byte[] salt = Arrays.copyOfRange(decoded, 0, SALT_LENGTH_BYTES);
            // Il resto è l'hash originale
            byte[] originalHash = Arrays.copyOfRange(decoded, SALT_LENGTH_BYTES, decoded.length);

            // Ricalcola PBKDF2 con la password fornita
            PBEKeySpec spec = new PBEKeySpec(inputPassword.toCharArray(), salt, iterationCount, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] newHash = factory.generateSecret(spec).getEncoded();

            // Confronta gli hash
            return Arrays.equals(originalHash, newHash);
        } catch (Exception e) {
            // In caso di errore consideriamo la password non valida
            return false;
        }
    }

    @Override
    public byte[] deriveKey(String password, byte[] salt) {
        if (password == null || salt == null) {
            throw new IllegalArgumentException("Password and salt must not be null");
        }

        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Error while deriving key", e);
        }
    }
}
