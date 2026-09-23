package qp.deob;

import org.objectweb.asm.tree.*;
import java.util.*;

public final class ClassFacts {
    public String thisClass;
    public String scheme = "none";
    public boolean ok = false;
    public String error;

    public String poolField;
    public final Map<Integer, String> poolValues = new HashMap<>();

    public final List<StringSite> stringSites = new ArrayList<>();
    public final List<IndySite> indySites = new ArrayList<>();
    public final Set<String> syntheticMethods = new HashSet<>();
    public final Set<String> syntheticFields = new HashSet<>();
    public final Set<String> opaqueIntFields = new HashSet<>();
    public final List<String> warnings = new ArrayList<>();

    public static final class StringSite {
        public String method, desc, plaintext;
        public int ordinal;
        public AbstractInsnNode node;
    }

    public static final class IndySite {
        public String method, desc, owner, name, tdesc, kind;
        public int ordinal;
        public AbstractInsnNode node;
    }

    public boolean isSyntheticMethod(String name, String desc) {
        return syntheticMethods.contains(name + "\u0000" + desc);
    }

    public void bind(ClassNode cn, List<String> reportOut) {
        Map<String, MethodNode> byKey = new HashMap<>();
        for (MethodNode mn : cn.methods) byKey.put(mn.name + "\u0000" + mn.desc, mn);
        for (StringSite ss : stringSites) {
            MethodNode mn = byKey.get(ss.method + "\u0000" + ss.desc);
            if (mn == null) continue;
            AbstractInsnNode n = Insns.atOrdinal(mn, ss.ordinal);
            if (n == null) {
                reportOut.add("string site unbound " + ss.method + " @" + ss.ordinal);
                continue;
            }
            int op = n.getOpcode();
            if (op == org.objectweb.asm.Opcodes.INVOKEDYNAMIC || op == org.objectweb.asm.Opcodes.INVOKESTATIC
                || op == org.objectweb.asm.Opcodes.AALOAD)
                ss.node = n;
            else
                reportOut.add("string site opcode mismatch " + ss.method + " @" + ss.ordinal + " op=" + op);
        }
        for (IndySite is : indySites) {
            MethodNode mn = byKey.get(is.method + "\u0000" + is.desc);
            if (mn == null) continue;
            AbstractInsnNode n = Insns.atOrdinal(mn, is.ordinal);
            if (n == null) {
                reportOut.add("indy site unbound " + is.method + " @" + is.ordinal);
                continue;
            }
            if (n.getOpcode() == org.objectweb.asm.Opcodes.INVOKEDYNAMIC) is.node = n;
            else reportOut.add("indy site opcode mismatch " + is.method + " @" + is.ordinal);
        }
    }
}
