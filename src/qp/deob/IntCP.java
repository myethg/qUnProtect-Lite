package qp.deob;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import java.util.*;

public final class IntCP implements Opcodes {

    static final class V {
        final Long intVal;
        final Long longVal;
        final boolean wide;

        private V(Long intVal, Long longVal, boolean wide) {
            this.intVal = intVal;
            this.longVal = longVal;
            this.wide = wide;
        }

        static final V UNKNOWN = new V(null, null, false);
        static final V UNKNOWN_WIDE = new V(null, null, true);

        static V ofInt(int x) { return new V((long) x, null, false); }
        static V ofLong(long x) { return new V(null, x, true); }

        static V merge(V a, V b) {
            if (a == null) return b;
            if (b == null) return a;
            if (a.intVal != null && a.intVal.equals(b.intVal)) return a;
            if (a.longVal != null && a.longVal.equals(b.longVal)) return a;
            return a.wide || b.wide ? UNKNOWN_WIDE : UNKNOWN;
        }

        boolean eq(V o) {
            return Objects.equals(intVal, o.intVal) && Objects.equals(longVal, o.longVal) && wide == o.wide;
        }
    }

    static final class State {
        ArrayList<V> stack;
        V[] locals;

        State(ArrayList<V> stack, V[] locals) {
            this.stack = stack;
            this.locals = locals;
        }

        State copy() { return new State(new ArrayList<>(stack), locals.clone()); }

        boolean merge(State o) {
            boolean changed = false;
            for (int i = 0; i < locals.length; i++) {
                V m = V.merge(locals[i], o.locals[i]);
                if (!eq(locals[i], m)) { locals[i] = m; changed = true; }
            }
            int n = Math.min(stack.size(), o.stack.size());
            for (int i = 0; i < n; i++) {
                V m = V.merge(stack.get(i), o.stack.get(i));
                if (!eq(stack.get(i), m)) { stack.set(i, m); changed = true; }
            }
            return changed;
        }

        static boolean eq(V a, V b) {
            if (a == null || b == null) return a == b;
            return a.eq(b);
        }
    }

    private final MethodNode method;
    private final AbstractInsnNode[] insns;
    private final Map<LabelNode, Integer> labelIndex = new HashMap<>();
    private final State[] entry;

    public IntCP(MethodNode method) {
        this.method = method;
        this.insns = method.instructions.toArray();
        for (int i = 0; i < insns.length; i++)
            if (insns[i] instanceof LabelNode) labelIndex.put((LabelNode) insns[i], i);
        entry = new State[insns.length];
        run();
    }

    public Integer intAt(int idx, int depth) {
        State s = entry[idx];
        if (s == null) return null;
        int p = s.stack.size() - 1 - depth;
        if (p < 0) return null;
        V v = s.stack.get(p);
        return (v != null && v.intVal != null) ? (int) (long) v.intVal : null;
    }

    private void run() {
        V[] loc0 = new V[Math.max(method.maxLocals, 1)];
        Arrays.fill(loc0, V.UNKNOWN);
        int li = 0;
        if ((method.access & ACC_STATIC) == 0) loc0[li++] = V.UNKNOWN;
        for (Type t : Type.getArgumentTypes(method.desc)) {
            boolean w = t.getSize() == 2;
            loc0[li] = w ? V.UNKNOWN_WIDE : V.UNKNOWN;
            li += w ? 2 : 1;
        }
        entry[0] = new State(new ArrayList<>(), loc0);
        Deque<Integer> work = new ArrayDeque<>();
        work.add(0);
        int guard = 0, cap = insns.length * 40 + 1000;
        while (!work.isEmpty()) {
            if (++guard > cap) break;
            int pc = work.poll();
            State s = entry[pc];
            if (s == null) continue;
            State cur = s.copy();
            for (int succ : step(pc, cur)) {
                if (succ < 0 || succ >= insns.length) continue;
                if (entry[succ] == null) { entry[succ] = cur.copy(); work.add(succ); }
                else if (entry[succ].merge(cur)) work.add(succ);
            }
        }
    }

    private int[] step(int pc, State s) {
        AbstractInsnNode n = insns[pc];
        int op = n.getOpcode();
        if (op < 0) return new int[]{pc + 1};
        ArrayList<V> st = s.stack;
        switch (op) {
            case NOP: case CHECKCAST: break;
            case ACONST_NULL: st.add(V.UNKNOWN); break;
            case ICONST_M1: case ICONST_0: case ICONST_1: case ICONST_2: case ICONST_3: case ICONST_4: case ICONST_5:
                st.add(V.ofInt(op - ICONST_0)); break;
            case LCONST_0: st.add(V.ofLong(0)); break;
            case LCONST_1: st.add(V.ofLong(1)); break;
            case BIPUSH: case SIPUSH: st.add(V.ofInt(((IntInsnNode) n).operand)); break;
            case LDC: {
                Object c = ((LdcInsnNode) n).cst;
                if (c instanceof Integer) st.add(V.ofInt((Integer) c));
                else if (c instanceof Long) st.add(V.ofLong((Long) c));
                else if (c instanceof Double) st.add(V.UNKNOWN_WIDE);
                else st.add(V.UNKNOWN);
                break;
            }
            case ILOAD: case FLOAD: case ALOAD: st.add(loc(s, ((VarInsnNode) n).var)); break;
            case LLOAD: case DLOAD: st.add(wideOf(loc(s, ((VarInsnNode) n).var))); break;
            case ISTORE: case FSTORE: case ASTORE: s.locals[((VarInsnNode) n).var] = pop(st); break;
            case LSTORE: case DSTORE: s.locals[((VarInsnNode) n).var] = pop(st); break;
            case IINC: {
                int v = ((IincInsnNode) n).var;
                V cv = loc(s, v);
                s.locals[v] = (cv.intVal != null) ? V.ofInt((int) (long) cv.intVal + ((IincInsnNode) n).incr) : V.UNKNOWN;
                break;
            }
            case IALOAD: case FALOAD: case BALOAD: case CALOAD: case SALOAD: pop(st); pop(st); st.add(V.UNKNOWN); break;
            case AALOAD: pop(st); pop(st); st.add(V.UNKNOWN); break;
            case LALOAD: case DALOAD: pop(st); pop(st); st.add(V.UNKNOWN_WIDE); break;
            case IASTORE: case FASTORE: case AASTORE: case BASTORE: case CASTORE: case SASTORE: pop(st); pop(st); pop(st); break;
            case LASTORE: case DASTORE: pop(st); pop(st); pop(st); break;
            case POP: pop(st); break;
            case POP2: { V v = pop(st); if (!v.wide) pop(st); break; }
            case DUP: { V v = top(st); st.add(v); break; }
            case DUP_X1: { V a = pop(st), b = pop(st); st.add(a); st.add(b); st.add(a); break; }
            case DUP_X2: {
                V a = pop(st), b = pop(st);
                if (b.wide) { st.add(a); st.add(b); st.add(a); }
                else { V c = pop(st); st.add(a); st.add(c); st.add(b); st.add(a); }
                break;
            }
            case DUP2: {
                V a = top(st);
                if (a.wide) { st.add(a); }
                else { V x = pop(st), y = top(st); st.add(x); st.add(y); st.add(x); }
                break;
            }
            case DUP2_X1: {
                V a = pop(st);
                if (a.wide) { V b = pop(st); st.add(a); st.add(b); st.add(a); }
                else { V b = pop(st), c = pop(st); st.add(b); st.add(a); st.add(c); st.add(b); st.add(a); }
                break;
            }
            case DUP2_X2: {
                V a = pop(st), b = pop(st);
                if (a.wide) {
                    if (b.wide) { st.add(a); st.add(b); st.add(a); }
                    else { V c = pop(st); st.add(a); st.add(c); st.add(b); st.add(a); }
                } else {
                    V c = pop(st);
                    if (c.wide) { st.add(b); st.add(a); st.add(c); st.add(b); st.add(a); }
                    else { V d = pop(st); st.add(b); st.add(a); st.add(d); st.add(c); st.add(b); st.add(a); }
                }
                break;
            }
            case SWAP: { V a = pop(st), b = pop(st); st.add(a); st.add(b); break; }
            case IADD: case ISUB: case IMUL: case IDIV: case IREM: case ISHL: case ISHR: case IUSHR: case IAND: case IOR: case IXOR: {
                V b = pop(st), a = pop(st);
                st.add((a.intVal != null && b.intVal != null)
                    ? V.ofInt(Insns.applyBinIntSafe(op, (int) (long) a.intVal, (int) (long) b.intVal)) : V.UNKNOWN);
                break;
            }
            case INEG: { V a = pop(st); st.add(a.intVal != null ? V.ofInt(-(int) (long) a.intVal) : V.UNKNOWN); break; }
            case LADD: case LSUB: case LMUL: case LDIV: case LREM: case LAND: case LOR: case LXOR: {
                V b = pop(st), a = pop(st);
                st.add((a.longVal != null && b.longVal != null) ? V.ofLong(lop(op, a.longVal, b.longVal)) : V.UNKNOWN_WIDE);
                break;
            }
            case LSHL: case LSHR: case LUSHR: {
                V b = pop(st), a = pop(st);
                st.add((a.longVal != null && b.intVal != null) ? V.ofLong(lop(op, a.longVal, b.intVal)) : V.UNKNOWN_WIDE);
                break;
            }
            case LNEG: { V a = pop(st); st.add(a.longVal != null ? V.ofLong(-a.longVal) : V.UNKNOWN_WIDE); break; }
            case I2L: { V a = pop(st); st.add(a.intVal != null ? V.ofLong((long) (int) (long) a.intVal) : V.UNKNOWN_WIDE); break; }
            case L2I: { V a = pop(st); st.add(a.longVal != null ? V.ofInt((int) (long) a.longVal) : V.UNKNOWN); break; }
            case I2B: { V a = pop(st); st.add(a.intVal != null ? V.ofInt((byte) (int) (long) a.intVal) : V.UNKNOWN); break; }
            case I2C: { V a = pop(st); st.add(a.intVal != null ? V.ofInt((int) (long) a.intVal & 0xffff) : V.UNKNOWN); break; }
            case I2S: { V a = pop(st); st.add(a.intVal != null ? V.ofInt((short) (int) (long) a.intVal) : V.UNKNOWN); break; }
            case I2F: pop(st); st.add(V.UNKNOWN); break;
            case I2D: case L2D: pop(st); st.add(V.UNKNOWN_WIDE); break;
            case L2F: pop(st); st.add(V.UNKNOWN); break;
            case F2I: pop(st); st.add(V.UNKNOWN); break;
            case F2L: pop(st); st.add(V.UNKNOWN_WIDE); break;
            case F2D: pop(st); st.add(V.UNKNOWN_WIDE); break;
            case D2I: pop(st); st.add(V.UNKNOWN); break;
            case D2L: pop(st); st.add(V.UNKNOWN_WIDE); break;
            case D2F: pop(st); st.add(V.UNKNOWN); break;
            case FADD: case FSUB: case FMUL: case FDIV: case FREM: pop(st); pop(st); st.add(V.UNKNOWN); break;
            case DADD: case DSUB: case DMUL: case DDIV: case DREM: pop(st); pop(st); st.add(V.UNKNOWN_WIDE); break;
            case FNEG: pop(st); st.add(V.UNKNOWN); break;
            case DNEG: pop(st); st.add(V.UNKNOWN_WIDE); break;
            case LCMP: case FCMPL: case FCMPG: case DCMPL: case DCMPG: pop(st); pop(st); st.add(V.UNKNOWN); break;
            case IFEQ: case IFNE: case IFLT: case IFGE: case IFGT: case IFLE: case IFNULL: case IFNONNULL:
                pop(st); return new int[]{pc + 1, labelIndex.get(((JumpInsnNode) n).label)};
            case IF_ICMPEQ: case IF_ICMPNE: case IF_ICMPLT: case IF_ICMPGE: case IF_ICMPGT: case IF_ICMPLE:
            case IF_ACMPEQ: case IF_ACMPNE:
                pop(st); pop(st); return new int[]{pc + 1, labelIndex.get(((JumpInsnNode) n).label)};
            case GOTO: return new int[]{labelIndex.get(((JumpInsnNode) n).label)};
            case JSR: return new int[]{pc + 1};
            case TABLESWITCH: {
                pop(st);
                TableSwitchInsnNode ts = (TableSwitchInsnNode) n;
                int[] r = new int[ts.labels.size() + 1];
                r[0] = labelIndex.get(ts.dflt);
                for (int i = 0; i < ts.labels.size(); i++) r[i + 1] = labelIndex.get(ts.labels.get(i));
                return r;
            }
            case LOOKUPSWITCH: {
                pop(st);
                LookupSwitchInsnNode ls = (LookupSwitchInsnNode) n;
                int[] r = new int[ls.labels.size() + 1];
                r[0] = labelIndex.get(ls.dflt);
                for (int i = 0; i < ls.labels.size(); i++) r[i + 1] = labelIndex.get(ls.labels.get(i));
                return r;
            }
            case IRETURN: case FRETURN: case ARETURN: case LRETURN: case DRETURN: case RETURN: case ATHROW: return new int[]{};
            case GETSTATIC: { String d = ((FieldInsnNode) n).desc; st.add(wideDesc(d) ? V.UNKNOWN_WIDE : V.UNKNOWN); break; }
            case PUTSTATIC: pop(st); break;
            case GETFIELD: { pop(st); String d = ((FieldInsnNode) n).desc; st.add(wideDesc(d) ? V.UNKNOWN_WIDE : V.UNKNOWN); break; }
            case PUTFIELD: pop(st); pop(st); break;
            case INVOKEVIRTUAL: case INVOKESPECIAL: case INVOKESTATIC: case INVOKEINTERFACE: {
                MethodInsnNode mi = (MethodInsnNode) n;
                for (Type t : Type.getArgumentTypes(mi.desc)) pop(st);
                if (op != INVOKESTATIC) pop(st);
                Type rt = Type.getReturnType(mi.desc);
                if (rt.getSort() != Type.VOID) st.add(rt.getSize() == 2 ? V.UNKNOWN_WIDE : V.UNKNOWN);
                break;
            }
            case INVOKEDYNAMIC: {
                InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) n;
                for (Type t : Type.getArgumentTypes(id.desc)) pop(st);
                Type rt = Type.getReturnType(id.desc);
                if (rt.getSort() != Type.VOID) st.add(rt.getSize() == 2 ? V.UNKNOWN_WIDE : V.UNKNOWN);
                break;
            }
            case NEW: st.add(V.UNKNOWN); break;
            case NEWARRAY: case ANEWARRAY: pop(st); st.add(V.UNKNOWN); break;
            case ARRAYLENGTH: pop(st); st.add(V.UNKNOWN); break;
            case INSTANCEOF: pop(st); st.add(V.UNKNOWN); break;
            case MONITORENTER: case MONITOREXIT: pop(st); break;
            case MULTIANEWARRAY: { for (int i = 0; i < ((MultiANewArrayInsnNode) n).dims; i++) pop(st); st.add(V.UNKNOWN); break; }
            default: break;
        }
        return new int[]{pc + 1};
    }

    private static V loc(State s, int i) {
        return (i >= 0 && i < s.locals.length && s.locals[i] != null) ? s.locals[i] : V.UNKNOWN;
    }

    private static V wideOf(V v) {
        return v.wide ? v : (v.longVal != null ? v : V.UNKNOWN_WIDE);
    }

    private static V pop(ArrayList<V> st) {
        return st.isEmpty() ? V.UNKNOWN : st.remove(st.size() - 1);
    }

    private static V top(ArrayList<V> st) {
        return st.isEmpty() ? V.UNKNOWN : st.get(st.size() - 1);
    }

    private static boolean wideDesc(String d) {
        return d.equals("J") || d.equals("D");
    }

    private static long lop(int op, long a, long b) {
        switch (op) {
            case LADD: return a + b;
            case LSUB: return a - b;
            case LMUL: return a * b;
            case LDIV: return b == 0 ? 0 : a / b;
            case LREM: return b == 0 ? 0 : a % b;
            case LSHL: return a << ((int) b & 63);
            case LSHR: return a >> ((int) b & 63);
            case LUSHR: return a >>> ((int) b & 63);
            case LAND: return a & b;
            case LOR: return a | b;
            case LXOR: return a ^ b;
        }
        return 0;
    }
}
