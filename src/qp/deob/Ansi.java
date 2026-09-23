package qp.deob;

public final class Ansi {
    private static final String RESET  = "\u001b[0m";
    private static final String BOLD   = "\u001b[1m";
    private static final String CYAN   = "\u001b[96m";
    private static final String WHITE  = "\u001b[97m";
    private static final String GREEN  = "\u001b[92m";
    private static final String YELLOW = "\u001b[93m";
    private static final String RED    = "\u001b[91m";
    private static final String GREY   = "\u001b[90m";

    private static boolean enabled;

    private Ansi() {}

    public static void setEnabled(boolean on) { enabled = on; }

    private static String wrap(String code, String s) {
        return enabled ? code + s + RESET : s;
    }

    public static String bold(String s)   { return wrap(BOLD, s); }
    public static String cyan(String s)   { return wrap(CYAN, s); }
    public static String white(String s)  { return wrap(WHITE, s); }
    public static String green(String s)  { return wrap(GREEN, s); }
    public static String yellow(String s) { return wrap(YELLOW, s); }
    public static String red(String s)    { return wrap(RED, s); }
    public static String grey(String s)   { return wrap(GREY, s); }

    public static String numbers(String s) {
        if (!enabled) return s;
        StringBuilder b = new StringBuilder(s.length() + 16);
        int i = 0, n = s.length();
        while (i < n) {
            if (Character.isDigit(s.charAt(i))) {
                int j = i;
                while (j < n && Character.isDigit(s.charAt(j))) j++;
                b.append(WHITE).append(s, i, j).append(RESET);
                i = j;
            } else {
                b.append(s.charAt(i++));
            }
        }
        return b.toString();
    }
}
