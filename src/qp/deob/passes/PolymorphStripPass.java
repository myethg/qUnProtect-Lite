package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;

public final class PolymorphStripPass implements DeobPass, Opcodes {
    public String id() { return "polymorph"; }
    public String label() { return "Polymorph"; }
    public String desc() { return "strip stack-neutral polymorph junk (LDC;String.length();POP)"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            if (facts != null && facts.isSyntheticMethod(mn.name, mn.desc)) continue;
            int c = 0;
            for (AbstractInsnNode n : mn.instructions.toArray()) {
                if (!(n instanceof LdcInsnNode) || !(((LdcInsnNode) n).cst instanceof String)) continue;
                AbstractInsnNode m1 = n.getNext();
                if (!(m1 instanceof MethodInsnNode)) continue;
                MethodInsnNode mi = (MethodInsnNode) m1;
                if (mi.getOpcode() != INVOKEVIRTUAL || !mi.owner.equals("java/lang/String")
                    || !mi.name.equals("length") || !mi.desc.equals("()I")) continue;
                AbstractInsnNode m2 = m1.getNext();
                if (m2 == null || m2.getOpcode() != POP) continue;
                mn.instructions.remove(n);
                mn.instructions.remove(m1);
                mn.instructions.remove(m2);
                c++;
            }
            c += stripDeadPushes(cn, mn);
            if (c > 0) r.detail(cn.name + "#" + mn.name + ": " + c + " junk removed");
            r.add("junkRemoved", c);
        }
        return r;
    }

    private int stripDeadPushes(ClassNode cn, MethodNode mn) {
        int total = 0;
        boolean changed = true;
        while (changed) {
            changed = false;
            for (AbstractInsnNode n : mn.instructions.toArray()) {
                int op = n.getOpcode();
                if (op == POP) {
                    AbstractInsnNode p = prevReal(n);
                    if (p != null && sefreeCat1(cn, p)) {
                        mn.instructions.remove(p); mn.instructions.remove(n);
                        total++; changed = true; break;
                    }
                } else if (op == POP2) {
                    AbstractInsnNode p = prevReal(n);
                    if (p != null && sefreeCat2(cn, p)) {
                        mn.instructions.remove(p); mn.instructions.remove(n);
                        total++; changed = true; break;
                    }
                    if (p != null && sefreeCat1(cn, p)) {
                        AbstractInsnNode p2 = prevReal(p);
                        if (p2 != null && sefreeCat1(cn, p2)) {
                            mn.instructions.remove(p2); mn.instructions.remove(p); mn.instructions.remove(n);
                            total++; changed = true; break;
                        }
                    }
                }
            }
        }
        return total;
    }

    private static AbstractInsnNode prevReal(AbstractInsnNode n) {
        AbstractInsnNode p = n.getPrevious();
        while (p != null && (p.getOpcode() < 0)) {
            if (p instanceof LabelNode) return null;
            p = p.getPrevious();
        }
        return p;
    }

    private static boolean sefreeCat1(ClassNode cn, AbstractInsnNode n) {
        int op = n.getOpcode();
        if (op == ACONST_NULL || (op >= ICONST_M1 && op <= ICONST_5) || op == FCONST_0 || op == FCONST_1
            || op == FCONST_2 || op == BIPUSH || op == SIPUSH || op == ILOAD || op == FLOAD || op == ALOAD)
            return true;
        if (op == LDC) {
            Object c = ((LdcInsnNode) n).cst;
            return !(c instanceof Long) && !(c instanceof Double);
        }
        if (op == GETSTATIC) {
            FieldInsnNode fi = (FieldInsnNode) n;
            String d = fi.desc;
            return fi.owner.equals(cn.name) && !d.equals("J") && !d.equals("D");
        }
        return false;
    }

    private static boolean sefreeCat2(ClassNode cn, AbstractInsnNode n) {
        int op = n.getOpcode();
        if (op == LCONST_0 || op == LCONST_1 || op == DCONST_0 || op == DCONST_1 || op == LLOAD || op == DLOAD)
            return true;
        if (op == LDC) {
            Object c = ((LdcInsnNode) n).cst;
            return c instanceof Long || c instanceof Double;
        }
        if (op == GETSTATIC) {
            FieldInsnNode fi = (FieldInsnNode) n;
            return fi.owner.equals(cn.name) && (fi.desc.equals("J") || fi.desc.equals("D"));
        }
        return false;
    }

    public String describe(PassResult r) {
        int n = r.count("junkRemoved");
        return n == 0 ? "" : "removed " + n + " polymorph stubs";
    }
}
