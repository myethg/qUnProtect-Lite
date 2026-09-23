package qp.deob.passes;

import java.util.*;

public final class PassResult {
    public final LinkedHashMap<String, Integer> counts = new LinkedHashMap<>();
    public final List<String> details = new ArrayList<>();

    public PassResult add(String key, int n) {
        counts.merge(key, n, Integer::sum);
        return this;
    }

    public PassResult detail(String line) {
        details.add(line);
        return this;
    }

    public int count(String key) {
        return counts.getOrDefault(key, 0);
    }

    public int total() {
        int t = 0;
        for (int v : counts.values()) t += v;
        return t;
    }

    public boolean changed() {
        return total() != 0;
    }

    public String summary() {
        if (counts.isEmpty()) return "";
        StringBuilder b = new StringBuilder();
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (b.length() > 0) b.append(' ');
            b.append(e.getKey()).append('=').append(e.getValue());
        }
        return b.toString();
    }
}
