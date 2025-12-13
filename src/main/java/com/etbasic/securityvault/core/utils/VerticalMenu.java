package com.etbasic.securityvault.core.utils;

import org.jline.terminal.Terminal;
import org.jline.utils.AttributedStringBuilder;
import org.jline.utils.AttributedStyle;
import org.jline.utils.InfoCmp;
import java.io.IOException;
import java.util.List;

/* Questa classe serve a rendere il menu iniziale interattivo,
*  rendendo possibile spostarsi tra le varie voci del menu con le frecce ↓ e ↑ e
*  premendo poi ENTER è possibile entrare in quella voce.
* */

public class VerticalMenu {

    private final Terminal terminal;
    private final List<MenuItem> menuItems;
    private int selected = 0; // serve per impostare la selezione sulla prima righa

    public VerticalMenu(Terminal terminal, List<MenuItem> menuItems) {
        this.terminal = terminal;
        this.menuItems = menuItems;
    }

    public void show() {
        while (true) {
            render();

            /* I caratteri delle frecce sono composte in questo modo:
            * ↑ => ESC[A
            * ↓ => ESC[B
            * */

            int key0_pressed;
            try {
                key0_pressed = terminal.reader().read(); // legge solo il primo carattere
            } catch (IOException e) {
                return;
            }

            if (key0_pressed == 27) { // le frecce quando premute inviano dei caratteri che iniziano con ESC, in ASCII equivale a 27
                try {
                    int key1_pressed = terminal.reader().read();
                    int key2_pressed = terminal.reader().read();
                    if (key1_pressed == '[') {
                        if (key2_pressed == 'A') {           // ↑
                            selected = (selected - 1 + menuItems.size()) % menuItems.size(); // il modulo serve a tornare all'ultima voce se sei arrivato alla prima
                        } else if (key2_pressed == 'B') {    // ↓
                            selected = (selected + 1) % menuItems.size(); // il modulo serve a tornare alla prima voce se sei arrivato all'ultima
                        }
                    }
                } catch (IOException ignored) {}
            } else if (key0_pressed == '\n' || key0_pressed == '\r') { // ENTER, il \n è quello per Unix mentre \r è quello di windows
                menuItems.get(selected).action.run(); // questo è quello che fa partire il metodo/voce selezionato
            }
        }
    }

    private void render() {
        terminal.puts(InfoCmp.Capability.clear_screen); // me l'ha consigliato chatty, serve a cancellare completamente il terminale per evitare "sbavature"
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
            asb.style(AttributedStyle.DEFAULT); // questo fa il reset dello stile, sempre conisgliato da chatty

             // STAMPA MENU
            terminal.writer().println(asb.toAnsi(terminal)); // questo fa comparire la voce sul terminale nel modo in cui hai desritto sopra
        }

        terminal.flush();
    }

    public record MenuItem(String label, Runnable action) { //questa classe record me l´ha consigliata Intellij ma non ho capito come funzioni
    }
}
