package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import java.util.*;

public final class DeadCodePass implements DeobPass, Opcodes {
    public String id() { return "dce"; }
    public String label() { return "DeadCode"; }
    public String desc() { return "remove unreachable instructions (reachability DCE)"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if (facts != null && facts.isSyntheticMethod(mn.name, mn.desc)) continue;
            int c = dce(mn);
            if (c > 0) r.detail(cn.name + "#" + mn.name + ": " + c + " dead insns");
            r.add("deadInsns", c);
        }
        return r;
    }

    private int dce(MethodNode mn) {
        InsnList insns = mn.instructions;
        Set<AbstractInsnNode> reach = new HashSet<>();
        Deque<AbstractInsnNode> work = new ArrayDeque<>();
        work.add(insns.getFirst());
        if (mn.tryCatchBlocks != null)
            for (TryCatchBlockNode t : mn.tryCatchBlocks) work.add(t.handler);
        while (!work.isEmpty()) {
            AbstractInsnNode n = work.poll();
            while (n != null && !reach.contains(n)) {
                reach.add(n);
                int op = n.getOpcode();
                if (n instanceof JumpInsnNode) {
                    work.add(((JumpInsnNode) n).label);
                    if (op == GOTO) break;
                } else if (n instanceof TableSwitchInsnNode) {
                    TableSwitchInsnNode ts = (TableSwitchInsnNode) n;
                    work.add(ts.dflt);
                    work.addAll(ts.labels);
                    break;
                } else if (n instanceof LookupSwitchInsnNode) {
                    LookupSwitchInsnNode ls = (LookupSwitchInsnNode) n;
                    work.add(ls.dflt);
                    work.addAll(ls.labels);
                    break;
                } else if ((op >= IRETURN && op <= RETURN) || op == ATHROW) {
                    break;
                }
                n = n.getNext();
            }
        }
        int removed = 0;
        for (AbstractInsnNode n : insns.toArray()) {
            if (reach.contains(n)) continue;
            if (n instanceof LabelNode) continue;
            if (n.getOpcode() < 0) continue;
            insns.remove(n);
            removed++;
        }
        return removed;
    }

    public String describe(PassResult r) {
        int n = r.count("deadInsns");
        return n == 0 ? "" : "removed " + n + " dead insns";
    }
}
