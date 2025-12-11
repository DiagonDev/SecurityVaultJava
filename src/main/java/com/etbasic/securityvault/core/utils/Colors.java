package com.etbasic.securityvault.core.utils;

import java.util.Map;

public final class Colors {
    static final Map<String, String> ANSI_CODES = Map.ofEntries(
            Map.entry("black", "\u001B[30m"),
            Map.entry("red", "\u001B[31m"),
            Map.entry("green", "\u001B[32m"),
            Map.entry("yellow", "\u001B[33m"),
            Map.entry("blue", "\u001B[34m"),
            Map.entry("magenta", "\u001B[35m"),
            Map.entry("cyan", "\u001B[36m"),
            Map.entry("white", "\u001B[37m"),
            Map.entry("reset", "\u001B[0m")
    );

    public static String get(String colorName) {
        return ANSI_CODES.getOrDefault(colorName.toLowerCase(), "");
    }
}
