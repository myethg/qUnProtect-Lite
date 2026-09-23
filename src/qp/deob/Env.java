package qp.deob;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import java.util.*;

public final class Env {
    private final Map<String, ClassNode> classes = new HashMap<>();
    private final Map<String, Boolean> ifaceCache = new HashMap<>();

    public Env(Collection<ClassNode> nodes) {
        for (ClassNode cn : nodes) classes.put(cn.name, cn);
    }

    public boolean isInterface(String internalName) {
        if (internalName == null) return false;
        Boolean cached = ifaceCache.get(internalName);
        if (cached != null) return cached;
        boolean result;
        ClassNode cn = classes.get(internalName);
        if (cn != null) {
            result = (cn.access & Opcodes.ACC_INTERFACE) != 0;
        } else {
            try {
                Class<?> c = Class.forName(internalName.replace('/', '.'), false, Env.class.getClassLoader());
                result = c.isInterface();
            } catch (Throwable t) {
                result = false;
            }
        }
        ifaceCache.put(internalName, result);
        return result;
    }

    private String superOf(String name) {
        ClassNode cn = classes.get(name);
        if (cn != null) return cn.superName;
        try {
            Class<?> c = Class.forName(name.replace('/', '.'), false, Env.class.getClassLoader());
            Class<?> s = c.getSuperclass();
            return s == null ? null : s.getName().replace('.', '/');
        } catch (Throwable t) {
            return null;
        }
    }

    private boolean isAncestor(String ancestor, String descendant) {
        String x = descendant;
        while (x != null) {
            if (x.equals(ancestor)) return true;
            if (x.equals("java/lang/Object")) break;
            x = superOf(x);
        }
        return ancestor.equals("java/lang/Object");
    }

    public String commonSuper(String t1, String t2) {
        if (t1.equals(t2)) return t1;
        if (t1.equals("java/lang/Object") || t2.equals("java/lang/Object")) return "java/lang/Object";
        try {
            if (isInterface(t1) || isInterface(t2)) return "java/lang/Object";
            if (isAncestor(t1, t2)) return t1;
            if (isAncestor(t2, t1)) return t2;
            String c = t1;
            do {
                c = superOf(c);
                if (c == null) return "java/lang/Object";
            } while (!isAncestor(c, t2));
            return c;
        } catch (Throwable t) {
            return "java/lang/Object";
        }
    }
}
