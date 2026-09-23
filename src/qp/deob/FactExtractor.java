package qp.deob;

import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

public final class FactExtractor implements Opcodes {
    static final String XOR_DESC = "(IILjava/lang/Object;)Ljava/lang/String;";
    static final String AES_DESC = "([BLjava/lang/String;Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;";
    static final String BSM_OBJ = "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)Ljava/lang/Object;";
    static final String BSM_STD = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;I)Ljava/lang/invoke/CallSite;";

    public ClassFacts extract(ClassNode cn) {
        ClassFacts f = new ClassFacts();
        f.thisClass = cn.name;
        f.ok = true;
        try {
            doExtract(cn, f);
        } catch (Throwable t) {
            f.warnings.add("extract error: " + t);
        }
        return f;
    }

    private void doExtract(ClassNode cn, ClassFacts f) {
        MethodNode aesDec = null, xorDec = null;
        for (MethodNode m : cn.methods) {
            if ((m.access & ACC_STATIC) == 0) continue;
            if (m.desc.equals(AES_DESC)) aesDec = m;
            else if (m.desc.equals(XOR_DESC)) xorDec = m;
        }
        MethodNode linker = null;
        for (MethodNode m : cn.methods)
            if ((m.desc.equals(BSM_OBJ) || m.desc.equals(BSM_STD)) && isLinkerReferenced(cn, m)) { linker = m; break; }
        if (linker == null)
            for (MethodNode m : cn.methods)
                if (m.desc.equals(BSM_OBJ) || m.desc.equals(BSM_STD)) { linker = m; break; }

        Sim sim = new Sim(cn);
        if (aesDec != null) { sim.aesDecName = aesDec.name; sim.aesDecDesc = aesDec.desc; }
        MethodNode clinit = method(cn, "<clinit>", "()V");
        if ((aesDec != null || xorDec != null || linker != null) && clinit != null) {
            try { sim.run(clinit, new Object[0]); }
            catch (Sim.Stop e) { f.warnings.add("clinit stop: " + e.getMessage()); }
            catch (Sim.JThrow ignored) { }
            catch (Throwable e) { f.warnings.add("clinit err: " + e); }
        }

        String poolField = null, ivField = null;
        if (aesDec != null) {
            f.scheme = "aes";
            poolField = staticFieldOfDesc(cn, "[Ljava/lang/String;");
            ivField = staticFieldOfDesc(cn, "[B");
            f.poolField = poolField;
            Object pool = sim.statics.get(poolField);
            if (pool instanceof Sim.SimArr) {
                Object[] v = ((Sim.SimArr) pool).v;
                for (int i = 0; i < v.length; i++)
                    if (v[i] instanceof Sim.SimStr) f.poolValues.put(i, ((Sim.SimStr) v[i]).str());
            }
        } else if (xorDec != null) {
            f.scheme = "xor";
        } else {
            f.scheme = linker != null ? "indy" : "none";
        }

        Map<String, String[]> resolved = new HashMap<>();
        if (linker != null) resolveIndy(cn, linker, sim, resolved, f);

        String xorDecName = xorDec != null ? xorDec.name : null;

        for (MethodNode m : cn.methods) {
            if (m.instructions == null) continue;
            IntCP cp = null;
            AbstractInsnNode[] arr = m.instructions.toArray();
            int ord = -1;
            for (int ai = 0; ai < arr.length; ai++) {
                AbstractInsnNode n = arr[ai];
                if (n.getOpcode() < 0) continue;
                ord++;
                int op = n.getOpcode();
                if (op == AALOAD && "aes".equals(f.scheme) && !f.poolValues.isEmpty()) {
                    if (cp == null) cp = new IntCP(m);
                    Integer idx = cp.intAt(ai, 0);
                    if (idx != null && f.poolValues.containsKey(idx)) addStr(f, m, ord, f.poolValues.get(idx));
                    continue;
                }
                if (op == INVOKESTATIC && xorDecName != null) {
                    MethodInsnNode mi = (MethodInsnNode) n;
                    if (mi.owner.equals(cn.name) && mi.name.equals(xorDecName) && mi.desc.equals(XOR_DESC)) {
                        if (cp == null) cp = new IntCP(m);
                        Integer b = cp.intAt(ai, 1), a = cp.intAt(ai, 2);
                        String pt = a != null && b != null ? xorDecrypt(sim, xorDecName, a, b, f) : null;
                        if (pt != null) addStr(f, m, ord, pt);
                        else f.warnings.add("xor site args unresolved " + m.name + " @" + ord);
                        continue;
                    }
                }
                if (op == INVOKEDYNAMIC) {
                    InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) n;
                    String[] r = resolved.get(id.name);
                    if (r == null) { f.warnings.add("unresolved indy " + m.name + " @" + ord + " " + shortName(id.name)); continue; }
                    String kind = r[0], owner = r[1], mem = r[2], desc = r[3];
                    if (xorDecName != null && owner.equals(cn.name) && mem.equals(xorDecName) && desc.equals(XOR_DESC)) {
                        if (cp == null) cp = new IntCP(m);
                        Integer b = cp.intAt(ai, 1), a = cp.intAt(ai, 2);
                        String pt = a != null && b != null ? xorDecrypt(sim, xorDecName, a, b, f) : null;
                        if (pt != null) addStr(f, m, ord, pt);
                        else f.warnings.add("xor(indy) site args unresolved " + m.name + " @" + ord);
                        continue;
                    }
                    if (kind.equals("unknown")) { f.warnings.add("indy kind unknown " + m.name + " @" + ord); continue; }
                    ClassFacts.IndySite is = new ClassFacts.IndySite();
                    is.method = m.name; is.desc = m.desc; is.ordinal = ord;
                    is.owner = owner; is.name = mem; is.tdesc = desc; is.kind = kind;
                    f.indySites.add(is);
                }
            }
        }

        detectSynthetics(cn, aesDec, xorDec, linker, resolved, poolField, ivField, f);
        detectOpaqueFields(cn, f);
    }

    private void resolveIndy(ClassNode cn, MethodNode linker, Sim sim, Map<String, String[]> resolved, ClassFacts f) {
        Set<String> done = new HashSet<>();
        for (MethodNode m : cn.methods) {
            if (m.instructions == null) continue;
            for (AbstractInsnNode n : m.instructions.toArray()) {
                if (!(n instanceof InvokeDynamicInsnNode)) continue;
                InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) n;
                Handle h = id.bsm;
                if (h == null || !h.getOwner().equals(cn.name) || !h.getName().equals(linker.name)) continue;
                if (done.contains(id.name)) continue;
                done.add(id.name);
                int magic = 0;
                if (id.bsmArgs != null && id.bsmArgs.length > 0 && id.bsmArgs[0] instanceof Integer)
                    magic = (Integer) id.bsmArgs[0];
                try {
                    Sim.SimObj lk = new Sim.SimObj("java/lang/invoke/MethodHandles$Lookup");
                    lk.f.put("name", new Sim.SimStr(cn.name));
                    Object[] args = { lk, new Sim.SimStr(id.name), new Sim.SimObj("java/lang/invoke/MethodType"), magic };
                    sim.run(linker, args);
                    f.warnings.add("indy " + shortName(id.name) + " did not reach find*");
                } catch (Sim.FindX fx) {
                    String owner = fx.owner == null ? "" : fx.owner.replace('.', '/');
                    resolved.put(id.name, new String[]{ fx.which, owner, fx.name, fx.desc });
                } catch (Sim.Stop e) {
                    f.warnings.add("indy resolve stop " + shortName(id.name) + ": " + e.getMessage());
                } catch (Throwable e) {
                    f.warnings.add("indy resolve err " + shortName(id.name) + ": " + e);
                }
            }
        }
    }

    private String xorDecrypt(Sim sim, String decName, int a, int b, ClassFacts f) {
        try {
            Object r = sim.call(decName, XOR_DESC, new Object[]{ a, b, Sim.NULLV });
            return r instanceof Sim.SimStr ? ((Sim.SimStr) r).str() : null;
        } catch (Throwable t) {
            f.warnings.add("xor decrypt failed a=" + a + " b=" + b + ": " + t);
            return null;
        }
    }

    private void addStr(ClassFacts f, MethodNode m, int ord, String pt) {
        ClassFacts.StringSite ss = new ClassFacts.StringSite();
        ss.method = m.name; ss.desc = m.desc; ss.ordinal = ord; ss.plaintext = pt;
        f.stringSites.add(ss);
    }

    private void detectSynthetics(ClassNode cn, MethodNode aesDec, MethodNode xorDec, MethodNode linker,
                                  Map<String, String[]> resolved, String poolField, String ivField, ClassFacts f) {
        Map<String, MethodNode> own = new HashMap<>();
        for (MethodNode m : cn.methods) if (m.instructions != null) own.put(m.name + "\u0000" + m.desc, m);

        Set<String> synFieldSeed = new HashSet<>();
        if (poolField != null) synFieldSeed.add(poolField);
        if (ivField != null) synFieldSeed.add(ivField);
        if (xorDec != null)
            for (AbstractInsnNode n : xorDec.instructions.toArray())
                if (n instanceof FieldInsnNode && ((FieldInsnNode) n).owner.equals(cn.name)
                    && (((FieldInsnNode) n).desc.equals("[Ljava/lang/String;") || ((FieldInsnNode) n).desc.equals("[B")))
                    synFieldSeed.add(((FieldInsnNode) n).name);

        Set<String> decNames = new HashSet<>();
        if (aesDec != null) decNames.add(aesDec.name);
        if (xorDec != null) decNames.add(xorDec.name);

        Set<String> seeds = new HashSet<>();
        if (aesDec != null) seeds.add(aesDec.name + "\u0000" + aesDec.desc);
        if (xorDec != null) seeds.add(xorDec.name + "\u0000" + xorDec.desc);
        if (linker != null) seeds.add(linker.name + "\u0000" + linker.desc);
        for (Map.Entry<String, MethodNode> e : own.entrySet()) {
            if (seeds.contains(e.getKey())) continue;
            MethodNode m = e.getValue();
            if (m.name.equals("<clinit>") || m.name.equals("<init>") || m.name.equals("main")) continue;
            boolean bootstrap = false;
            for (AbstractInsnNode n : m.instructions.toArray()) {
                if (n instanceof MethodInsnNode && n.getOpcode() == INVOKESTATIC) {
                    MethodInsnNode mi = (MethodInsnNode) n;
                    if (mi.owner.equals(cn.name) && decNames.contains(mi.name)) bootstrap = true;
                }
                if (n instanceof FieldInsnNode && n.getOpcode() == PUTSTATIC) {
                    FieldInsnNode fi = (FieldInsnNode) n;
                    if (fi.owner.equals(cn.name) && synFieldSeed.contains(fi.name)) bootstrap = true;
                }
            }
            if (bootstrap) seeds.add(e.getKey());
        }
        Map<String, Set<String>> refs = new HashMap<>();
        for (Map.Entry<String, MethodNode> e : own.entrySet()) refs.put(e.getKey(), ownRefs(cn, e.getValue(), resolved, own));
        Set<String> closure = new HashSet<>(seeds);
        Deque<String> stack = new ArrayDeque<>(seeds);
        while (!stack.isEmpty()) {
            String mk = stack.pop();
            for (String t : refs.getOrDefault(mk, Collections.emptySet())) {
                String tn = t.substring(0, t.indexOf('\u0000'));
                if (!closure.contains(t) && !tn.equals("<clinit>") && !tn.equals("<init>") && !tn.equals("main")) {
                    closure.add(t);
                    stack.push(t);
                }
            }
        }
        for (String mk : closure) {
            String nm = mk.substring(0, mk.indexOf('\u0000'));
            if (!nm.equals("<clinit>") && !nm.equals("<init>") && !nm.equals("main")) f.syntheticMethods.add(mk);
        }

        Map<String, String> fdesc = new HashMap<>();
        for (FieldNode fn : cn.fields) fdesc.put(fn.name, fn.desc);
        Map<String, Set<String>> fieldRefs = new HashMap<>();
        for (Map.Entry<String, MethodNode> e : own.entrySet())
            for (AbstractInsnNode n : e.getValue().instructions.toArray())
                if (n instanceof FieldInsnNode && ((FieldInsnNode) n).owner.equals(cn.name))
                    fieldRefs.computeIfAbsent(((FieldInsnNode) n).name, k -> new HashSet<>()).add(e.getKey());
        Set<String> synFields = new HashSet<>(synFieldSeed);
        synFields.retainAll(fdesc.keySet());
        for (Map.Entry<String, Set<String>> e : fieldRefs.entrySet()) {
            boolean outside = false;
            for (String r : e.getValue())
                if (!f.syntheticMethods.contains(r) && !r.equals("<clinit>\u0000()V")) outside = true;
            if (!outside && fdesc.containsKey(e.getKey())) synFields.add(e.getKey());
        }
        f.syntheticFields.addAll(synFields);
    }

    private Set<String> ownRefs(ClassNode cn, MethodNode m, Map<String, String[]> resolved, Map<String, MethodNode> own) {
        Set<String> r = new HashSet<>();
        for (AbstractInsnNode n : m.instructions.toArray()) {
            if (n instanceof MethodInsnNode) {
                MethodInsnNode mi = (MethodInsnNode) n;
                if (mi.owner.equals(cn.name)) {
                    String k = mi.name + "\u0000" + mi.desc;
                    if (own.containsKey(k)) r.add(k);
                }
            } else if (n instanceof InvokeDynamicInsnNode) {
                String[] t = resolved.get(((InvokeDynamicInsnNode) n).name);
                if (t != null && t[1].equals(cn.name)) {
                    String k = t[2] + "\u0000" + t[3];
                    if (own.containsKey(k)) r.add(k);
                }
            }
        }
        return r;
    }

    private void detectOpaqueFields(ClassNode cn, ClassFacts f) {
        Set<String> prim = new HashSet<>();
        for (FieldNode fn : cn.fields)
            if ((fn.access & ACC_STATIC) != 0 && (fn.desc.equals("I") || fn.desc.equals("Z"))) prim.add(fn.name);
        Set<String> writtenElsewhere = new HashSet<>();
        for (MethodNode m : cn.methods) {
            if (m.instructions == null) continue;
            for (AbstractInsnNode n : m.instructions.toArray())
                if (n instanceof FieldInsnNode && n.getOpcode() == PUTSTATIC
                    && ((FieldInsnNode) n).owner.equals(cn.name) && prim.contains(((FieldInsnNode) n).name)
                    && !m.name.equals("<clinit>"))
                    writtenElsewhere.add(((FieldInsnNode) n).name);
        }
        for (String n : prim) if (!writtenElsewhere.contains(n)) f.opaqueIntFields.add(n);
    }

    private static boolean isLinkerReferenced(ClassNode cn, MethodNode m) {
        for (MethodNode x : cn.methods) {
            if (x.instructions == null) continue;
            for (AbstractInsnNode n : x.instructions.toArray())
                if (n instanceof InvokeDynamicInsnNode) {
                    Handle h = ((InvokeDynamicInsnNode) n).bsm;
                    if (h != null && h.getOwner().equals(cn.name) && h.getName().equals(m.name) && h.getDesc().equals(m.desc))
                        return true;
                }
        }
        return false;
    }

    private static MethodNode method(ClassNode cn, String name, String desc) {
        for (MethodNode m : cn.methods) if (m.name.equals(name) && m.desc.equals(desc)) return m;
        return null;
    }

    private static String staticFieldOfDesc(ClassNode cn, String desc) {
        for (FieldNode f : cn.fields) if ((f.access & ACC_STATIC) != 0 && f.desc.equals(desc)) return f.name;
        return null;
    }

    private static String shortName(String s) {
        return s.length() > 12 ? s.substring(0, 12) : s;
    }
}
