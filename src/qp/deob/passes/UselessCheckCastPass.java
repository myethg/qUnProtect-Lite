package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import qp.deob.Insns;

public final class UselessCheckCastPass implements DeobPass, Opcodes {
    public String id() { return "checkcast"; }
    public String label() { return "CheckCast"; }
    public String desc() { return "remove useless CHECKCAST Throwable before ATHROW"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            if (facts != null && facts.isSyntheticMethod(mn.name, mn.desc)) continue;
            int c = 0;
            for (AbstractInsnNode n : mn.instructions.toArray()) {
                if (n instanceof TypeInsnNode && n.getOpcode() == CHECKCAST
                    && ((TypeInsnNode) n).desc.equals("java/lang/Throwable")) {
                    AbstractInsnNode nx = Insns.nextReal(n);
                    if (nx != null && nx.getOpcode() == ATHROW) {
                        mn.instructions.remove(n);
                        c++;
                    }
                }
            }
            if (c > 0) r.detail(cn.name + "#" + mn.name + ": " + c + " checkcasts");
            r.add("checkcastsRemoved", c);
        }
        return r;
    }

    public String describe(PassResult r) {
        int n = r.count("checkcastsRemoved");
        return n == 0 ? "" : "removed " + n + " checkcasts";
    }
}
