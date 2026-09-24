package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import qp.deob.Insns;
import java.util.*;

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
            Set<LabelNode> targets = targetLabels(mn);
            for (AbstractInsnNode n : mn.instructions.toArray()) {
                int op = n.getOpcode();
                if (op == L2I) {
                    AbstractInsnNode a = Insns.prevReal(n);
                    Long lv = Insns.longConstOf(a);
                    if (lv == null || lands(n, targets)) continue;
                    replace(mn, new AbstractInsnNode[]{a, n}, (int) (long) lv);
                    changed = true; folds++;
                    continue;
                }
                if (op == INEG || op == I2B || op == I2C || op == I2S) {
                    AbstractInsnNode a = Insns.prevReal(n);
                    Integer v = Insns.intConstOf(a);
                    if (v == null || lands(n, targets)) continue;
                    int res = op == INEG ? -v : op == I2B ? (byte) (int) v : op == I2C ? (char) (int) v : (short) (int) v;
                    replace(mn, new AbstractInsnNode[]{a, n}, res);
                    changed = true; folds++;
                    continue;
                }
                if (!Insns.isBinIntOp(op)) continue;
                AbstractInsnNode b = Insns.prevReal(n);
                AbstractInsnNode a = b == null ? null : Insns.prevReal(b);
                if (a == null) continue;
                Integer vb = Insns.intConstOf(b), va = Insns.intConstOf(a);
                if (va == null || vb == null) continue;
                if (lands(n, targets) || lands(b, targets)) continue;
                replace(mn, new AbstractInsnNode[]{a, b, n}, Insns.applyBinInt(op, va, vb));
                changed = true;
                folds++;
            }
        }
        return folds;
    }

    private static void replace(MethodNode mn, AbstractInsnNode[] remove, int value) {
        InsnList repl = new InsnList();
        Insns.pushInt(repl, value);
        mn.instructions.insert(remove[remove.length - 1], repl);
        for (AbstractInsnNode d : remove) mn.instructions.remove(d);
    }

    private static Set<LabelNode> targetLabels(MethodNode mn) {
        Set<LabelNode> s = new HashSet<>();
        for (AbstractInsnNode n : mn.instructions.toArray()) {
            if (n instanceof JumpInsnNode) s.add(((JumpInsnNode) n).label);
            else if (n instanceof TableSwitchInsnNode) { s.add(((TableSwitchInsnNode) n).dflt); s.addAll(((TableSwitchInsnNode) n).labels); }
            else if (n instanceof LookupSwitchInsnNode) { s.add(((LookupSwitchInsnNode) n).dflt); s.addAll(((LookupSwitchInsnNode) n).labels); }
        }
        if (mn.tryCatchBlocks != null)
            for (TryCatchBlockNode t : mn.tryCatchBlocks) { s.add(t.start); s.add(t.end); s.add(t.handler); }
        return s;
    }

    private static boolean lands(AbstractInsnNode insn, Set<LabelNode> targets) {
        AbstractInsnNode p = insn.getPrevious();
        while (p != null && p.getOpcode() < 0) {
            if (p instanceof LabelNode && targets.contains(p)) return true;
            p = p.getPrevious();
        }
        return false;
    }

    public String describe(PassResult r) {
        int n = r.count("folds");
        return n == 0 ? "" : "folded " + n + " constants";
    }
}
