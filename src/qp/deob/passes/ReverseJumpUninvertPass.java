package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import qp.deob.Insns;

public final class ReverseJumpUninvertPass implements DeobPass, Opcodes {
    public String id() { return "reversejump"; }
    public String label() { return "ReverseJump"; }
    public String desc() { return "un-invert reverse-jump obfuscation to direct conditional"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            if (facts != null && facts.isSyntheticMethod(mn.name, mn.desc)) continue;
            int c = 0;
            for (AbstractInsnNode n : mn.instructions.toArray()) {
                if (!(n instanceof JumpInsnNode)) continue;
                int op = n.getOpcode();
                if (op < 153 || op > 166) continue;
                JumpInsnNode cond = (JumpInsnNode) n;
                AbstractInsnNode g = Insns.nextReal(n);
                if (!(g instanceof JumpInsnNode) || g.getOpcode() != GOTO) continue;
                AbstractInsnNode lbl = Insns.nextReal(g);
                if (!(lbl instanceof LabelNode) || lbl != cond.label) continue;
                JumpInsnNode gotoN = (JumpInsnNode) g;
                cond.setOpcode(((op - 153) ^ 1) + 153);
                cond.label = gotoN.label;
                mn.instructions.remove(gotoN);
                c++;
            }
            if (c > 0) r.detail(cn.name + "#" + mn.name + ": " + c + " reverse-jumps");
            r.add("reverseJumps", c);
        }
        return r;
    }

    public String describe(PassResult r) {
        int n = r.count("reverseJumps");
        return n == 0 ? "" : "un-inverted " + n + " jumps";
    }
}
