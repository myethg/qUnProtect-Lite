package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import java.util.*;

public final class DeadCodePass implements DeobPass, Opcodes {
    public String id() { return "dce"; }
    public String label() { return "DeadCode"; }
    public String desc() { return "remove unreachable insns, dead handlers and orphan labels (reachability DCE)"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if (facts != null && facts.isSyntheticMethod(mn.name, mn.desc)) continue;
            int[] c = dce(mn);
            if (c[0] > 0 || c[1] > 0 || c[2] > 0)
                r.detail(cn.name + "#" + mn.name + ": " + c[0] + " insns, " + c[1] + " handlers, " + c[2] + " labels");
            r.add("deadInsns", c[0]);
            r.add("deadHandlers", c[1]);
            r.add("deadLabels", c[2]);
        }
        return r;
    }

    private int[] dce(MethodNode mn) {
        InsnList insns = mn.instructions;
        AbstractInsnNode first = insns.getFirst();
        if (first == null) return new int[]{0, 0, 0};

        Set<AbstractInsnNode> reach = new HashSet<>();
        Deque<AbstractInsnNode> work = new ArrayDeque<>();
        work.add(first);

        List<TryCatchBlockNode> tcbs = mn.tryCatchBlocks != null ? mn.tryCatchBlocks : Collections.<TryCatchBlockNode>emptyList();
        Set<TryCatchBlockNode> live = new HashSet<>();

        while (true) {
            sweep(work, reach);
            boolean added = false;
            for (TryCatchBlockNode t : tcbs) {
                if (live.contains(t) || t.handler == null || t.start == null || t.end == null) continue;
                if (rangeReachable(t, reach)) {
                    live.add(t);
                    work.add(t.handler);
                    added = true;
                }
            }
            if (!added) break;
        }

        int deadInsns = 0;
        for (AbstractInsnNode n : insns.toArray()) {
            if (n instanceof LabelNode) continue;
            if (reach.contains(n)) continue;
            boolean real = n.getOpcode() >= 0;
            insns.remove(n);
            if (real) deadInsns++;
        }

        int deadHandlers = 0;
        if (mn.tryCatchBlocks != null) {
            for (TryCatchBlockNode t : new ArrayList<>(mn.tryCatchBlocks)) {
                if (!live.contains(t)) {
                    mn.tryCatchBlocks.remove(t);
                    deadHandlers++;
                }
            }
        }

        Set<LabelNode> used = new HashSet<>();
        for (AbstractInsnNode n : insns.toArray()) {
            if (n instanceof JumpInsnNode) {
                used.add(((JumpInsnNode) n).label);
            } else if (n instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode ts = (TableSwitchInsnNode) n;
                used.add(ts.dflt);
                used.addAll(ts.labels);
            } else if (n instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode ls = (LookupSwitchInsnNode) n;
                used.add(ls.dflt);
                used.addAll(ls.labels);
            } else if (n instanceof LineNumberNode) {
                used.add(((LineNumberNode) n).start);
            }
        }
        if (mn.tryCatchBlocks != null) {
            for (TryCatchBlockNode t : mn.tryCatchBlocks) {
                used.add(t.start);
                used.add(t.end);
                used.add(t.handler);
            }
        }
        if (mn.localVariables != null) {
            for (LocalVariableNode lv : mn.localVariables) {
                used.add(lv.start);
                used.add(lv.end);
            }
        }
        used.remove(null);

        int deadLabels = 0;
        for (AbstractInsnNode n : insns.toArray()) {
            if (!(n instanceof LabelNode)) continue;
            if (used.contains(n)) continue;
            insns.remove(n);
            deadLabels++;
        }

        return new int[]{deadInsns, deadHandlers, deadLabels};
    }

    private void sweep(Deque<AbstractInsnNode> work, Set<AbstractInsnNode> reach) {
        while (!work.isEmpty()) {
            AbstractInsnNode n = work.poll();
            while (n != null && reach.add(n)) {
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
                } else if (op == ATHROW || (op >= IRETURN && op <= RETURN) || op == RET) {
                    break;
                }
                n = n.getNext();
            }
        }
    }

    private boolean rangeReachable(TryCatchBlockNode t, Set<AbstractInsnNode> reach) {
        for (AbstractInsnNode n = t.start; n != null && n != t.end; n = n.getNext()) {
            if (n.getOpcode() >= 0 && reach.contains(n)) return true;
        }
        return false;
    }

    public String describe(PassResult r) {
        int i = r.count("deadInsns");
        int h = r.count("deadHandlers");
        int l = r.count("deadLabels");
        if (i == 0 && h == 0 && l == 0) return "";
        StringBuilder b = new StringBuilder("removed ").append(i).append(" dead insns");
        if (h > 0) b.append(", ").append(h).append(" handlers");
        if (l > 0) b.append(", ").append(l).append(" labels");
        return b.toString();
    }
}
