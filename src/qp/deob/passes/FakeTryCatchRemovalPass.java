package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import java.util.*;

public final class FakeTryCatchRemovalPass implements DeobPass, Opcodes {
    public String id() { return "faketrycatch"; }
    public String label() { return "FakeTryCatch"; }
    public String desc() { return "remove injected fake try/catch blocks with dead handlers"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if (mn.tryCatchBlocks == null || mn.tryCatchBlocks.isEmpty()) continue;
            Map<LabelNode, Boolean> verdict = new HashMap<>();
            int c = 0;
            Iterator<TryCatchBlockNode> it = mn.tryCatchBlocks.iterator();
            while (it.hasNext()) {
                TryCatchBlockNode t = it.next();
                Boolean fake = verdict.get(t.handler);
                if (fake == null) {
                    fake = isFakeHandler(t.handler);
                    verdict.put(t.handler, fake);
                }
                if (fake) {
                    it.remove();
                    c++;
                }
            }
            int m = coalesce(mn);
            if (c > 0) r.detail(cn.name + "#" + mn.name + ": " + c + " fake try/catch");
            if (m > 0) r.detail(cn.name + "#" + mn.name + ": " + m + " fragmented ranges merged");
            r.add("fakeTryCatch", c);
            r.add("tryRangesMerged", m);
        }
        return r;
    }

    private static int coalesce(MethodNode mn) {
        List<TryCatchBlockNode> tcs = mn.tryCatchBlocks;
        if (tcs.size() < 2) return 0;
        Map<AbstractInsnNode, Integer> pos = new HashMap<>();
        int i = 0;
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) pos.put(n, i++);
        int merged = 0;
        int k = 0;
        while (k + 1 < tcs.size()) {
            TryCatchBlockNode a = tcs.get(k), b = tcs.get(k + 1);
            if (a.handler == b.handler && Objects.equals(a.type, b.type) && canJoin(a, b, pos)) {
                a.end = b.end;
                tcs.remove(k + 1);
                merged++;
            } else {
                k++;
            }
        }
        return merged;
    }

    private static boolean canJoin(TryCatchBlockNode a, TryCatchBlockNode b, Map<AbstractInsnNode, Integer> pos) {
        Integer ae = pos.get(a.end), bs = pos.get(b.start), as = pos.get(a.start), be = pos.get(b.end);
        if (ae == null || bs == null || as == null || be == null) return false;
        if (as > ae || bs > be || ae > bs) return false;
        Integer hp = pos.get(a.handler);
        if (hp == null || (hp >= as && hp < be)) return false;
        for (AbstractInsnNode n = a.end; n != null && n != b.start; n = n.getNext()) {
            int op = n.getOpcode();
            if (op >= 0 && mayThrow(n)) return false;
        }
        return true;
    }

    private static boolean mayThrow(AbstractInsnNode n) {
        int op = n.getOpcode();
        if (op >= NOP && op <= ALOAD) return op == LDC && !(((LdcInsnNode) n).cst instanceof Number || ((LdcInsnNode) n).cst instanceof String);
        if (op >= ISTORE && op <= ASTORE) return false;
        if (op >= POP && op <= SWAP) return false;
        if (op == IDIV || op == IREM || op == LDIV || op == LREM) return true;
        if (op >= IADD && op <= LXOR) return false;
        if (op == IINC) return false;
        if (op >= I2L && op <= DCMPG) return false;
        if (op >= IFEQ && op <= GOTO) return false;
        if (op == IFNULL || op == IFNONNULL) return false;
        if (op == TABLESWITCH || op == LOOKUPSWITCH) return false;
        return true;
    }

    private static AbstractInsnNode firstReal(AbstractInsnNode n) {
        while (n != null && n.getOpcode() < 0) n = n.getNext();
        return n;
    }

    private static boolean isFakeHandler(LabelNode handler) {
        AbstractInsnNode h = firstReal(handler);
        if (h == null) return false;
        Set<AbstractInsnNode> seen = new HashSet<>();
        AbstractInsnNode cur = h;
        while (cur != null && cur.getOpcode() == GOTO) {
            if (!seen.add(cur)) return true;
            cur = firstReal(((JumpInsnNode) cur).label);
        }
        if (cur == null) return false;
        int op = cur.getOpcode();
        if (op == ASTORE || op == POP || op == POP2) return false;
        if (op == ATHROW || op == MONITOREXIT || op == CHECKCAST) return false;
        if (op == DUP) {
            AbstractInsnNode nx = firstReal(cur.getNext());
            if (nx instanceof MethodInsnNode && nx.getOpcode() == INVOKEVIRTUAL
                && "printStackTrace".equals(((MethodInsnNode) nx).name)
                && "()V".equals(((MethodInsnNode) nx).desc)) return true;
        }
        return pushesWithoutConsuming(op);
    }

    private static boolean pushesWithoutConsuming(int op) {
        if (op >= ACONST_NULL && op <= DCONST_1) return true;
        if (op == BIPUSH || op == SIPUSH || op == LDC) return true;
        if (op >= ILOAD && op <= ALOAD) return true;
        if (op == GETSTATIC || op == NEW || op == DUP) return true;
        return false;
    }

    public String describe(PassResult r) {
        int n = r.count("fakeTryCatch");
        return n == 0 ? "" : "removed " + n + " fake try/catch";
    }
}
