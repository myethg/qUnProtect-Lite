package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import qp.deob.Insns;

public final class OpaquePredicateCollapsePass implements DeobPass, Opcodes {
    public String id() { return "opaque"; }
    public String label() { return "OpaquePredicate"; }
    public String desc() { return "collapse always-true opaque predicates to goto"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            if (facts != null && facts.isSyntheticMethod(mn.name, mn.desc)) continue;
            int c = 0;
            for (AbstractInsnNode n : mn.instructions.toArray()) {
                if (n.getOpcode() != IF_ICMPEQ) continue;
                AbstractInsnNode g1 = n.getPrevious();
                AbstractInsnNode g2 = g1 == null ? null : g1.getPrevious();
                if (!(g1 instanceof FieldInsnNode) || g1.getOpcode() != GETSTATIC) continue;
                if (!(g2 instanceof FieldInsnNode) || g2.getOpcode() != GETSTATIC) continue;
                FieldInsnNode f1 = (FieldInsnNode) g1, f2 = (FieldInsnNode) g2;
                if (!f1.owner.equals(f2.owner) || !f1.name.equals(f2.name) || !f1.desc.equals(f2.desc)) continue;
                if (!f1.desc.equals("I")) continue;
                LabelNode target = ((JumpInsnNode) n).label;
                AbstractInsnNode nx = Insns.nextReal(n);
                mn.instructions.remove(g2);
                mn.instructions.remove(g1);
                if (nx instanceof JumpInsnNode && nx.getOpcode() == GOTO && ((JumpInsnNode) nx).label == target) {
                    mn.instructions.remove(n);
                } else {
                    mn.instructions.insert(n, new JumpInsnNode(GOTO, target));
                    mn.instructions.remove(n);
                }
                c++;
            }
            if (c > 0) r.detail(cn.name + "#" + mn.name + ": " + c + " predicates");
            r.add("predicatesCollapsed", c);
        }
        return r;
    }

    public String describe(PassResult r) {
        int n = r.count("predicatesCollapsed");
        return n == 0 ? "" : "removed " + n + " predicates";
    }
}
