package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import java.util.*;

public final class DeadStoreEliminationPass implements DeobPass, Opcodes {
    public String id() { return "deadstore"; }
    public String label() { return "DeadStore"; }
    public String desc() { return "remove stores to never-read locals and their side-effect-free value"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if (facts != null && facts.isSyntheticMethod(mn.name, mn.desc)) continue;
            int c = run(mn);
            if (c > 0) r.detail(cn.name + "#" + mn.name + ": " + c + " dead stores");
            r.add("deadStores", c);
        }
        return r;
    }

    private int run(MethodNode mn) {
        Set<Integer> loaded = new HashSet<>();
        int firstParam = (mn.access & ACC_STATIC) != 0 ? 0 : 1;
        int slot = (mn.access & ACC_STATIC) != 0 ? 0 : 1;
        for (Type t : Type.getArgumentTypes(mn.desc)) slot += t.getSize();
        int paramTop = slot;
        for (AbstractInsnNode n : mn.instructions.toArray()) {
            int op = n.getOpcode();
            if (op == ILOAD || op == LLOAD || op == FLOAD || op == DLOAD || op == ALOAD)
                loaded.add(((VarInsnNode) n).var);
            else if (op == IINC) loaded.add(((IincInsnNode) n).var);
        }
        int removed = 0;
        boolean changed = true;
        while (changed) {
            changed = false;
            for (AbstractInsnNode n : mn.instructions.toArray()) {
                int op = n.getOpcode();
                if (op != ISTORE && op != FSTORE && op != ASTORE) continue;
                int v = ((VarInsnNode) n).var;
                if (loaded.contains(v)) continue;
                if (v >= firstParam && v < paramTop) continue;
                AbstractInsnNode p = prevReal(n);
                if (p == null || !sefreeCat1(p)) continue;
                mn.instructions.remove(p);
                mn.instructions.remove(n);
                removed++;
                changed = true;
                break;
            }
        }
        return removed;
    }

    private static AbstractInsnNode prevReal(AbstractInsnNode n) {
        AbstractInsnNode p = n.getPrevious();
        while (p != null && p.getOpcode() < 0) {
            if (p instanceof LabelNode) return null;
            p = p.getPrevious();
        }
        return p;
    }

    private static boolean sefreeCat1(AbstractInsnNode n) {
        int op = n.getOpcode();
        if (op == ACONST_NULL || (op >= ICONST_M1 && op <= ICONST_5) || op == FCONST_0 || op == FCONST_1
            || op == FCONST_2 || op == BIPUSH || op == SIPUSH || op == ILOAD || op == FLOAD || op == ALOAD)
            return true;
        if (op == LDC) {
            Object c = ((LdcInsnNode) n).cst;
            return !(c instanceof Long) && !(c instanceof Double);
        }
        return false;
    }

    public String describe(PassResult r) {
        int n = r.count("deadStores");
        return n == 0 ? "" : "removed " + n + " dead stores";
    }
}
