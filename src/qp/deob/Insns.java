package qp.deob;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import java.util.*;

public final class Insns implements Opcodes {
    private Insns() {}

    public static AbstractInsnNode atOrdinal(MethodNode mn, int ordinal) {
        if (mn.instructions == null) return null;
        int ord = 0;
        for (AbstractInsnNode n : mn.instructions.toArray()) {
            if (n.getOpcode() < 0) continue;
            if (ord == ordinal) return n;
            ord++;
        }
        return null;
    }

    public static AbstractInsnNode prevReal(AbstractInsnNode n) {
        AbstractInsnNode p = n == null ? null : n.getPrevious();
        while (p != null && p.getOpcode() < 0) p = p.getPrevious();
        return p;
    }

    public static AbstractInsnNode nextReal(AbstractInsnNode n) {
        AbstractInsnNode p = n == null ? null : n.getNext();
        while (p != null && p.getOpcode() < 0) p = p.getNext();
        return p;
    }

    public static Integer intConstOf(AbstractInsnNode in) {
        if (in == null) return null;
        int op = in.getOpcode();
        if (op >= ICONST_M1 && op <= ICONST_5) return op - ICONST_0;
        if (op == BIPUSH || op == SIPUSH) return ((IntInsnNode) in).operand;
        if (op == LDC && in instanceof LdcInsnNode && ((LdcInsnNode) in).cst instanceof Integer)
            return (Integer) ((LdcInsnNode) in).cst;
        return null;
    }

    public static Long longConstOf(AbstractInsnNode in) {
        if (in == null) return null;
        int op = in.getOpcode();
        if (op == LCONST_0) return 0L;
        if (op == LCONST_1) return 1L;
        if (op == LDC && in instanceof LdcInsnNode && ((LdcInsnNode) in).cst instanceof Long)
            return (Long) ((LdcInsnNode) in).cst;
        return null;
    }

    public static void pushInt(InsnList il, int v) {
        if (v >= -1 && v <= 5) il.add(new InsnNode(ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) il.add(new IntInsnNode(BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) il.add(new IntInsnNode(SIPUSH, v));
        else il.add(new LdcInsnNode(Integer.valueOf(v)));
    }

    public static boolean isBinIntOp(int op) {
        return op == IADD || op == ISUB || op == IMUL || op == IXOR || op == IAND
            || op == IOR || op == ISHL || op == ISHR || op == IUSHR;
    }

    public static int applyBinIntSafe(int op, int a, int b) {
        if ((op == IDIV || op == IREM) && b == 0) return 0;
        if (op == IDIV) return a / b;
        if (op == IREM) return a % b;
        return applyBinInt(op, a, b);
    }

    public static int applyBinInt(int op, int a, int b) {
        switch (op) {
            case IADD:  return a + b;
            case ISUB:  return a - b;
            case IMUL:  return a * b;
            case IXOR:  return a ^ b;
            case IAND:  return a & b;
            case IOR:   return a | b;
            case ISHL:  return a << (b & 31);
            case ISHR:  return a >> (b & 31);
            case IUSHR: return a >>> (b & 31);
            default: throw new IllegalStateException();
        }
    }

    public static int argCount(String desc) {
        return Type.getArgumentTypes(desc).length;
    }

    public static boolean deleteArgSlice(MethodNode mn, AbstractInsnNode before, int n) {
        List<AbstractInsnNode> toDelete = new ArrayList<>();
        AbstractInsnNode cur = prevReal(before);
        int need = n;
        while (need > 0) {
            if (cur == null) return false;
            int[] effect = stackEffect(cur);
            if (effect == null) return false;
            toDelete.add(cur);
            need = need - effect[1] + effect[0];
            cur = prevReal(cur);
            if (need < 0) return false;
        }
        for (AbstractInsnNode d : toDelete) mn.instructions.remove(d);
        return true;
    }

    private static int[] stackEffect(AbstractInsnNode n) {
        int op = n.getOpcode();
        if (op < 0) return null;
        switch (op) {
            case ACONST_NULL:
            case ICONST_M1: case ICONST_0: case ICONST_1: case ICONST_2: case ICONST_3:
            case ICONST_4: case ICONST_5:
            case BIPUSH: case SIPUSH:
                return new int[]{0, 1};
            case LDC: {
                Object c = ((LdcInsnNode) n).cst;
                if (c instanceof Long || c instanceof Double) return new int[]{0, 2};
                return new int[]{0, 1};
            }
            case IADD: case ISUB: case IMUL: case IXOR: case IAND: case IOR:
            case ISHL: case ISHR: case IUSHR: case IDIV: case IREM:
                return new int[]{2, 1};
            case INEG: case I2B: case I2C: case I2S: case I2L: case L2I:
                return new int[]{1, 1};
            case DUP:
                return new int[]{1, 2};
            default:
                return null;
        }
    }
}
