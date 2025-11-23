package com.etbasic.securityvault.core.model;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.etbasic.securityvault.core.json.Base64ByteArraySerializer;

public class VaultHeader {

    private int version = 1;
    private String kdfAlg = "PBKDF2WithHmacSHA256";

    @JsonSerialize(using = Base64ByteArraySerializer.Serializer.class)
    @JsonDeserialize(using = Base64ByteArraySerializer.Deserializer.class)
    private byte[] encSalt;

    private int encIterations;
    private int keyLenBytes = 32;

    private String cipherAlg = "AES/GCM/NoPadding";
    private int ivSizeBytes = 12;
    private int tagSizeBytes = 16;

    private String storedAuthHash;
    private String aadFormat = "header-json";

    public VaultHeader() {
    }

    public VaultHeader(byte[] encSalt,
                       int encIterations,
                       int keyLenBytes,
                       String storedAuthHash,
                       String aadFormat) {
        this.encSalt = encSalt;
        this.encIterations = encIterations;
        this.keyLenBytes = keyLenBytes;
        this.storedAuthHash = storedAuthHash;
        this.aadFormat = aadFormat;
    }

    // Getter + Setter
    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }

    public String getKdfAlg() { return kdfAlg; }
    public void setKdfAlg(String kdfAlg) { this.kdfAlg = kdfAlg; }

    public byte[] getEncSalt() { return encSalt; }
    public void setEncSalt(byte[] encSalt) { this.encSalt = encSalt; }

    public int getEncIterations() { return encIterations; }
    public void setEncIterations(int encIterations) { this.encIterations = encIterations; }

    public int getKeyLenBytes() { return keyLenBytes; }
    public void setKeyLenBytes(int keyLenBytes) { this.keyLenBytes = keyLenBytes; }

    public String getCipherAlg() { return cipherAlg; }
    public void setCipherAlg(String cipherAlg) { this.cipherAlg = cipherAlg; }

    public int getIvSizeBytes() { return ivSizeBytes; }
    public void setIvSizeBytes(int ivSizeBytes) { this.ivSizeBytes = ivSizeBytes; }

    public int getTagSizeBytes() { return tagSizeBytes; }
    public void setTagSizeBytes(int tagSizeBytes) { this.tagSizeBytes = tagSizeBytes; }

    public String getStoredAuthHash() { return storedAuthHash; }
    public void setStoredAuthHash(String storedAuthHash) { this.storedAuthHash = storedAuthHash; }

    public String getAadFormat() { return aadFormat; }
    public void setAadFormat(String aadFormat) { this.aadFormat = aadFormat; }
}
