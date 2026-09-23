package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import qp.deob.Insns;

public final class NumberFoldPass implements DeobPass, Opcodes {
    public String id() { return "numberfold"; }
    public String label() { return "NumberFold"; }
    public String desc() { return "constant-fold integer arithmetic chains to fixpoint"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            if (facts != null && facts.isSyntheticMethod(mn.name, mn.desc)) continue;
            int c = fold(mn);
            if (c > 0) r.detail(cn.name + "#" + mn.name + ": " + c + " folds");
            r.add("folds", c);
        }
        return r;
    }

    private int fold(MethodNode mn) {
        int folds = 0;
        boolean changed = true;
        while (changed) {
            changed = false;
            for (AbstractInsnNode n : mn.instructions.toArray()) {
                if (!Insns.isBinIntOp(n.getOpcode())) continue;
                AbstractInsnNode b = n.getPrevious();
                if (b == null) continue;
                AbstractInsnNode a = b.getPrevious();
                if (a == null) continue;
                Integer vb = Insns.intConstOf(b), va = Insns.intConstOf(a);
                if (va == null || vb == null) continue;
                int res = Insns.applyBinInt(n.getOpcode(), va, vb);
                InsnList repl = new InsnList();
                Insns.pushInt(repl, res);
                mn.instructions.insert(n, repl);
                mn.instructions.remove(a);
                mn.instructions.remove(b);
                mn.instructions.remove(n);
                changed = true;
                folds++;
            }
        }
        return folds;
    }

    public String describe(PassResult r) {
        int n = r.count("folds");
        return n == 0 ? "" : "folded " + n + " constants";
    }
}
