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
            if (c > 0) r.detail(cn.name + "#" + mn.name + ": " + c + " junk removed");
            r.add("junkRemoved", c);
        }
        return r;
    }

    public String describe(PassResult r) {
        int n = r.count("junkRemoved");
        return n == 0 ? "" : "removed " + n + " polymorph stubs";
    }
}
