package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import qp.deob.Insns;

public final class StringDecryptPass implements DeobPass, Opcodes {
    public String id() { return "strings"; }
    public String label() { return "StringDecrypt"; }
    public String desc() { return "restore encrypted strings to LDC (XOR emulation / AES pool)"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        if (facts == null || !facts.ok) return r;

        int poolReadsFolded = 0;
        for (ClassFacts.StringSite ss : facts.stringSites) {
            if (ss.node == null) { r.add("stringsSkipped", 1); continue; }
            MethodNode mn = methodOf(cn, ss.method, ss.desc);
            if (mn == null) { r.add("stringsSkipped", 1); continue; }
            if (ss.node.getOpcode() == AALOAD) {
                InsnList repl = new InsnList();
                repl.add(new InsnNode(POP2));
                repl.add(new LdcInsnNode(ss.plaintext));
                mn.instructions.insert(ss.node, repl);
                mn.instructions.remove(ss.node);
                poolReadsFolded++;
                r.add("stringsDecrypted", 1);
                r.detail(cn.name + "#" + ss.method + " @" + ss.ordinal + " pool -> LDC " + shorten(ss.plaintext));
            } else {
                String callDesc = ss.node instanceof InvokeDynamicInsnNode
                    ? ((InvokeDynamicInsnNode) ss.node).desc
                    : ((MethodInsnNode) ss.node).desc;
                int argc = Insns.argCount(callDesc);
                LdcInsnNode ldc = new LdcInsnNode(ss.plaintext);
                if (Insns.deleteArgSlice(mn, ss.node, argc)) {
                    mn.instructions.set(ss.node, ldc);
                } else {
                    InsnList repl = new InsnList();
                    for (int i = 0; i < argc; i++) repl.add(new InsnNode(POP));
                    repl.add(ldc);
                    mn.instructions.insert(ss.node, repl);
                    mn.instructions.remove(ss.node);
                }
                r.add("stringsDecrypted", 1);
                r.detail(cn.name + "#" + ss.method + " @" + ss.ordinal + " -> LDC " + shorten(ss.plaintext));
            }
        }

        if ("aes".equals(facts.scheme) && facts.poolField != null && poolReadsFolded > 0) {
            if (!residualPoolAaload(cn, facts)) {
                int nulled = 0;
                for (MethodNode mn : cn.methods) {
                    if (mn.instructions == null) continue;
                    if (facts.isSyntheticMethod(mn.name, mn.desc)) continue;
                    for (AbstractInsnNode n : mn.instructions.toArray()) {
                        if (n instanceof FieldInsnNode && n.getOpcode() == GETSTATIC) {
                            FieldInsnNode fi = (FieldInsnNode) n;
                            if (fi.owner.equals(cn.name) && fi.name.equals(facts.poolField)) {
                                mn.instructions.set(n, new InsnNode(ACONST_NULL));
                                nulled++;
                            }
                        }
                    }
                }
                r.add("poolReadsNeutralised", nulled);
            } else {
                r.detail(cn.name + ": residual pool AALOAD -> keeping pool field");
            }
        }
        return r;
    }

    private boolean residualPoolAaload(ClassNode cn, ClassFacts facts) {
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            if (facts.isSyntheticMethod(mn.name, mn.desc)) continue;
            for (AbstractInsnNode n : mn.instructions.toArray()) {
                if (n.getOpcode() != AALOAD) continue;
                AbstractInsnNode a = n.getPrevious();
                while (a != null && a.getOpcode() < 0) a = a.getPrevious();
                AbstractInsnNode arr = a == null ? null : a.getPrevious();
                while (arr != null && arr.getOpcode() < 0) arr = arr.getPrevious();
                if (arr instanceof FieldInsnNode && arr.getOpcode() == GETSTATIC
                    && ((FieldInsnNode) arr).owner.equals(cn.name)
                    && ((FieldInsnNode) arr).name.equals(facts.poolField)) return true;
            }
        }
        return false;
    }

    private static MethodNode methodOf(ClassNode cn, String name, String desc) {
        for (MethodNode mn : cn.methods)
            if (mn.name.equals(name) && mn.desc.equals(desc)) return mn;
        return null;
    }

    private static String shorten(String s) {
        s = s.replace("\n", "\\n");
        return s.length() > 24 ? '"' + s.substring(0, 24) + "...\"" : '"' + s + '"';
    }

    public String describe(PassResult r) {
        int n = r.count("stringsDecrypted");
        return n == 0 ? "" : "decrypted " + n + " strings";
    }
}
