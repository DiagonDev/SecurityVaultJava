package com.etbasic.securityvault.core.utils;

import org.jline.terminal.Terminal;
import org.jline.utils.AttributedStringBuilder;
import org.jline.utils.AttributedStyle;
import org.jline.utils.InfoCmp;
import java.util.List;
import org.jline.keymap.KeyMap;
import org.jline.keymap.BindingReader;

/* Questa classe serve a rendere il menu iniziale interattivo,
*  rendendo possibile spostarsi tra le varie voci del menu con le frecce ↓ e ↑ e
*  premendo poi ENTER è possibile entrare in quella voce.
* */

public class VerticalMenu {

    private final Terminal terminal;
    private final BindingReader bindingReader;
    private final KeyMap<String> keyMap;
    private final List<MenuItem> menuItems;
    private int selected = 0; // serve per impostare la selezione sulla prima riga

    public VerticalMenu(Terminal terminal, List<MenuItem> menuItems) {
        this.terminal = terminal;
        this.bindingReader = new BindingReader(terminal.reader());
        this.keyMap = new KeyMap<>();
        this.menuItems = menuItems;

        // Associa frecce e invio ad azioni logiche
        keyMap.bind("up", "\033[A");
        keyMap.bind("down", "\033[B");

        keyMap.bind("up", KeyMap.key(terminal, InfoCmp.Capability.key_up));
        keyMap.bind("down", KeyMap.key(terminal, InfoCmp.Capability.key_down));
        keyMap.bind("enter", "\r", "\n");
        keyMap.bind("quit", KeyMap.esc());
    }

    public void show() {
        while (true) {
            render();

            String key_pressed = bindingReader.readBinding(keyMap);

            if ("up".equals(key_pressed)) {
                selected = (selected - 1 + menuItems.size()) % menuItems.size();
            } else if ("down".equals(key_pressed)) {
                selected = (selected + 1) % menuItems.size();
            } else if ("enter".equals(key_pressed)) {
                menuItems.get(selected).action.run();
            } else if ("quit".equals(key_pressed)) {
                break;
            }
        }
    }

    private void render() {
        terminal.puts(InfoCmp.Capability.clear_screen); // serve a cancellare il terminale per evitare "sbavature"
        terminal.writer().println(Colors.get("yellow") + "SecurityVault - CLI" + Colors.get("reset"));
        terminal.writer().println("Scegli:\n");

        for (int i = 0; i < menuItems.size(); i++) {
            AttributedStringBuilder asb = new AttributedStringBuilder(); // serve per scrivere le stringhe ANSI

            // CREAZIONE DEL MENU
            if (i == selected) {
                asb.style(AttributedStyle.DEFAULT
                        .background(AttributedStyle.WHITE)
                        .foreground(AttributedStyle.BLACK));
                asb.append("> "); // è la freccia per indicare, oltre ai colori, qual è la voce selezionata
            } else {
                asb.append("  ");
            }
            asb.append(menuItems.get(i).label); // questo prende la voce corretta dalla lista
            asb.style(AttributedStyle.DEFAULT); // questo fa il reset dello stile, sempre consigliato da chatty

            // STAMPA MENU
            terminal.writer().println(asb.toAnsi(terminal)); // questo fa comparire la voce sul terminale nel modo in cui hai descritto sopra
        }
        terminal.flush();
    }

    public record MenuItem(String label, Runnable action) { //questa classe record me l´ha consigliata Intellij ma non ho capito come funzioni
    }
}
