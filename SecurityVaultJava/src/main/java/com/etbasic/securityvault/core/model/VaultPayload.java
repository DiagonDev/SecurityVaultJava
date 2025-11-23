package com.etbasic.securityvault.core.model;

import java.util.ArrayList;
import java.util.List;

public class VaultPayload {

    private List<VaultEntry> entries = new ArrayList<>();

    public VaultPayload() {
    }

    public VaultPayload(List<VaultEntry> entries) {
        this.entries = entries;
    }

    public List<VaultEntry> getEntries() {
        return entries;
    }

    public void setEntries(List<VaultEntry> entries) {
        this.entries = entries;
    }
}
