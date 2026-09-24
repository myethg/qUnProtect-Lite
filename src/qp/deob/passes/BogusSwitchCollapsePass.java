package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import qp.deob.IntCP;

public final class BogusSwitchCollapsePass implements DeobPass, Opcodes {
    public String id() { return "bogusswitch"; }
    public String label() { return "BogusSwitch"; }
    public String desc() { return "collapse constant-selector table/lookup switches to goto"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            int c = collapse(mn);
            if (c > 0) r.detail(cn.name + "#" + mn.name + ": " + c + " switches");
            r.add("switchesCollapsed", c);
        }
        return r;
    }

    private int collapse(MethodNode mn) {
        AbstractInsnNode[] arr = mn.instructions.toArray();
        boolean hasSwitch = false;
        for (AbstractInsnNode n : arr) {
            if (n instanceof TableSwitchInsnNode || n instanceof LookupSwitchInsnNode) { hasSwitch = true; break; }
        }
        if (!hasSwitch) return 0;
        IntCP cp = new IntCP(mn);
        int c = 0;
        for (int i = 0; i < arr.length; i++) {
            AbstractInsnNode n = arr[i];
            LabelNode target;
            if (n instanceof TableSwitchInsnNode) {
                Integer sel = cp.intAt(i, 0);
                if (sel == null) continue;
                TableSwitchInsnNode ts = (TableSwitchInsnNode) n;
                int v = sel;
                target = (v >= ts.min && v <= ts.max) ? ts.labels.get(v - ts.min) : ts.dflt;
            } else if (n instanceof LookupSwitchInsnNode) {
                Integer sel = cp.intAt(i, 0);
                if (sel == null) continue;
                LookupSwitchInsnNode ls = (LookupSwitchInsnNode) n;
                int v = sel;
                target = ls.dflt;
                for (int k = 0; k < ls.keys.size(); k++) {
                    if (ls.keys.get(k).intValue() == v) { target = ls.labels.get(k); break; }
                }
            } else {
                continue;
            }
            if (target == null) continue;
            InsnList repl = new InsnList();
            repl.add(new InsnNode(POP));
            repl.add(new JumpInsnNode(GOTO, target));
            mn.instructions.insert(n, repl);
            mn.instructions.remove(n);
            c++;
        }
        return c;
    }

    public String describe(PassResult r) {
        int n = r.count("switchesCollapsed");
        return n == 0 ? "" : "collapsed " + n + " switches";
    }
}
