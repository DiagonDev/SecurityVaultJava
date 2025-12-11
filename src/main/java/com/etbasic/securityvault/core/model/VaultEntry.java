package com.etbasic.securityvault.core.model;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.etbasic.securityvault.core.json.Base64ByteArraySerializer;

public class VaultEntry {

    private String id;
    private String title;
    private String username;
    private String password;
    private String notes;

    public VaultEntry() {
    }

    public VaultEntry(String id, String title, String username, String password, String notes) {
        this.id = id;
        this.title = title;
        this.username = username;
        this.password = password;
        this.notes = notes;
    }

    // Getter + Setter
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }
}
