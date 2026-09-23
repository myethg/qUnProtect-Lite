package qp.deob;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import java.util.*;

public final class Sim implements Opcodes {

    public static final class Stop extends RuntimeException {
        public Stop(String m) { super(m); }
    }

    public static final class JThrow extends RuntimeException {
        final Object o;
        public JThrow(Object o) { this.o = o; }
    }

    public static final class FindX extends RuntimeException {
        public final String which, owner, name, desc;
        public FindX(String which, String owner, String name, String desc) {
            this.which = which;
            this.owner = owner;
            this.name = name;
            this.desc = desc;
        }
    }

    public static final class SimStr {
        public int[] u;
        public SimStr(int[] u) { this.u = u; }
        public SimStr(String s) {
            u = new int[s.length()];
            for (int i = 0; i < s.length(); i++) u[i] = s.charAt(i);
        }
        public String str() {
            StringBuilder b = new StringBuilder();
            for (int c : u) b.append((char) c);
            return b.toString();
        }
    }

    public static final class SimArr {
        public final char t;
        public final Object[] v;
        public SimArr(char t, int n) {
            this.t = t;
            v = new Object[n];
            Object z = (t == 'L' ? NULLV : Integer.valueOf(0));
            Arrays.fill(v, z);
        }
        public SimArr(char t, Object[] v) {
            this.t = t;
            this.v = v;
        }
    }

    public static final class SimObj {
        public final String cls;
        public final Map<String, Object> f = new HashMap<>();
        public SimObj(String cls) { this.cls = cls; }
    }

    private final ClassNode cn;
    private final Map<String, MethodNode> methods = new HashMap<>();
    public final Map<String, Object> statics = new HashMap<>();
    public String aesDecName, aesDecDesc;
    private final int maxSteps = 3_000_000;

    public Sim(ClassNode cn) {
        this.cn = cn;
        for (MethodNode m : cn.methods) methods.put(m.name + m.desc, m);
    }

    public Object call(String name, String desc, Object[] args) {
        MethodNode m = methods.get(name + desc);
        if (m == null) throw new Stop("no method " + name + desc);
        return run(m, args);
    }

    private boolean wide(Object v) {
        return v instanceof Long || v instanceof Double;
    }

    public Object run(MethodNode m, Object[] args) {
        AbstractInsnNode[] ins = m.instructions.toArray();
        Map<LabelNode, Integer> lbl = new HashMap<>();
        for (int i = 0; i < ins.length; i++) if (ins[i] instanceof LabelNode) lbl.put((LabelNode) ins[i], i);
        Object[] loc = new Object[Math.max(m.maxLocals, args.length * 2 + 2)];
        int li = 0;
        Type[] at = Type.getArgumentTypes(m.desc);
        boolean isStatic = (m.access & ACC_STATIC) != 0;
        int ai = 0;
        if (!isStatic) loc[li++] = args[ai++];
        for (Type t : at) {
            loc[li] = (ai < args.length ? args[ai] : null);
            ai++;
            li += (t.getSize() == 2 ? 2 : 1);
        }
        Deque<Object> st = new ArrayDeque<>();
        int pc = 0, steps = 0;
        while (true) {
            if (++steps > maxSteps) throw new Stop("steps");
            if (pc < 0 || pc >= ins.length) throw new Stop("pc oob");
            AbstractInsnNode n = ins[pc];
            int op = n.getOpcode();
            if (op < 0) { pc++; continue; }
            int next = pc + 1;
            try {
                switch (op) {
                    case NOP: break;
                    case ACONST_NULL: st.push(NULLV); break;
                    case ICONST_M1: case ICONST_0: case ICONST_1: case ICONST_2: case ICONST_3:
                    case ICONST_4: case ICONST_5: st.push(op - ICONST_0); break;
                    case LCONST_0: st.push(0L); break;
                    case LCONST_1: st.push(1L); break;
                    case BIPUSH: case SIPUSH: st.push(((IntInsnNode) n).operand); break;
                    case LDC: {
                        Object c = ((LdcInsnNode) n).cst;
                        if (c instanceof String) st.push(new SimStr((String) c));
                        else if (c instanceof Integer) st.push(((Integer) c).intValue());
                        else if (c instanceof Long) st.push(((Long) c).longValue());
                        else if (c instanceof Float) st.push((double) (float) (Float) c);
                        else if (c instanceof Double) st.push(((Double) c).doubleValue());
                        else st.push(new SimObj("class"));
                        break;
                    }
                    case ILOAD: case LLOAD: case ALOAD: case FLOAD: case DLOAD:
                        st.push(loc[((VarInsnNode) n).var]); break;
                    case ISTORE: case LSTORE: case ASTORE: case FSTORE: case DSTORE:
                        loc[((VarInsnNode) n).var] = st.pop(); break;
                    case IINC: {
                        IincInsnNode ii = (IincInsnNode) n;
                        loc[ii.var] = asInt(loc[ii.var]) + ii.incr;
                        break;
                    }
                    case IALOAD: case LALOAD: case FALOAD: case DALOAD: case AALOAD:
                    case BALOAD: case CALOAD: case SALOAD: {
                        int ix = asInt(st.pop());
                        Object a = st.pop();
                        if (!(a instanceof SimArr)) throw new Stop("aload non-arr");
                        SimArr arr = (SimArr) a;
                        if (ix < 0 || ix >= arr.v.length) throw new JThrow("AIOOBE");
                        st.push(arr.v[ix]);
                        break;
                    }
                    case IASTORE: case LASTORE: case FASTORE: case DASTORE: case AASTORE:
                    case BASTORE: case CASTORE: case SASTORE: {
                        Object v = st.pop();
                        int ix = asInt(st.pop());
                        Object a = st.pop();
                        if (!(a instanceof SimArr)) throw new Stop("astore non-arr");
                        SimArr arr = (SimArr) a;
                        if (ix < 0 || ix >= arr.v.length) throw new JThrow("AIOOBE");
                        if (op == BASTORE) v = (int) (byte) asInt(v);
                        else if (op == CASTORE) v = asInt(v) & 0xffff;
                        else if (op == SASTORE) v = (int) (short) asInt(v);
                        arr.v[ix] = v;
                        break;
                    }
                    case POP: st.pop(); break;
                    case POP2: { Object v = st.pop(); if (!wide(v)) st.pop(); break; }
                    case DUP: { Object v = st.peek(); st.push(v); break; }
                    case DUP_X1: { Object a = st.pop(), b = st.pop(); st.push(a); st.push(b); st.push(a); break; }
                    case DUP_X2: {
                        Object a = st.pop(), b = st.pop();
                        if (wide(b)) { st.push(a); st.push(b); st.push(a); }
                        else { Object c = st.pop(); st.push(a); st.push(c); st.push(b); st.push(a); }
                        break;
                    }
                    case DUP2: {
                        Object a = st.peek();
                        if (wide(a)) { st.push(a); }
                        else { Object x = st.pop(), y = st.peek(); st.push(x); st.push(y); st.push(x); }
                        break;
                    }
                    case DUP2_X1: {
                        Object a = st.pop();
                        if (wide(a)) { Object b = st.pop(); st.push(a); st.push(b); st.push(a); }
                        else { Object b = st.pop(), c = st.pop(); st.push(b); st.push(a); st.push(c); st.push(b); st.push(a); }
                        break;
                    }
                    case DUP2_X2: {
                        Object a = st.pop(), b = st.pop();
                        if (wide(a)) {
                            if (wide(b)) { st.push(a); st.push(b); st.push(a); }
                            else { Object c = st.pop(); st.push(a); st.push(c); st.push(b); st.push(a); }
                        } else {
                            Object c = st.pop();
                            if (wide(c)) { st.push(b); st.push(a); st.push(c); st.push(b); st.push(a); }
                            else { Object d = st.pop(); st.push(b); st.push(a); st.push(d); st.push(c); st.push(b); st.push(a); }
                        }
                        break;
                    }
                    case SWAP: { Object a = st.pop(), b = st.pop(); st.push(a); st.push(b); break; }
                    case IADD: case ISUB: case IMUL: case IDIV: case IREM:
                    case ISHL: case ISHR: case IUSHR: case IAND: case IOR: case IXOR: {
                        int b = asInt(st.pop()), a = asInt(st.pop());
                        st.push(iop(op, a, b));
                        break;
                    }
                    case INEG: st.push(-asInt(st.pop())); break;
                    case LADD: case LSUB: case LMUL: case LDIV: case LREM:
                    case LSHL: case LSHR: case LUSHR: case LAND: case LOR: case LXOR: {
                        if (op == LSHL || op == LSHR || op == LUSHR) {
                            int b = asInt(st.pop());
                            long a = asLong(st.pop());
                            st.push(lop(op, a, b));
                        } else {
                            long b = asLong(st.pop()), a = asLong(st.pop());
                            st.push(lop(op, a, b));
                        }
                        break;
                    }
                    case LNEG: st.push(-asLong(st.pop())); break;
                    case I2L: st.push((long) asInt(st.pop())); break;
                    case L2I: st.push((int) asLong(st.pop())); break;
                    case I2B: st.push((int) (byte) asInt(st.pop())); break;
                    case I2C: st.push(asInt(st.pop()) & 0xffff); break;
                    case I2S: st.push((int) (short) asInt(st.pop())); break;
                    case I2F: case I2D: st.push((double) asInt(st.pop())); break;
                    case L2F: case L2D: st.push((double) asLong(st.pop())); break;
                    case F2I: case D2I: st.push((int) asDouble(st.pop())); break;
                    case F2L: case D2L: st.push((long) asDouble(st.pop())); break;
                    case LCMP: { long b = asLong(st.pop()), a = asLong(st.pop()); st.push(Long.compare(a, b)); break; }
                    case FCMPL: case FCMPG: case DCMPL: case DCMPG: {
                        double b = asDouble(st.pop()), a = asDouble(st.pop());
                        st.push(Double.compare(a, b));
                        break;
                    }
                    case FADD: case DADD: { double b = asDouble(st.pop()), a = asDouble(st.pop()); st.push(a + b); break; }
                    case FSUB: case DSUB: { double b = asDouble(st.pop()), a = asDouble(st.pop()); st.push(a - b); break; }
                    case FMUL: case DMUL: { double b = asDouble(st.pop()), a = asDouble(st.pop()); st.push(a * b); break; }
                    case D2F: case F2D: st.push(asDouble(st.pop())); break;
                    case IFEQ: case IFNE: case IFLT: case IFGE: case IFGT: case IFLE: {
                        int a = asInt(st.pop());
                        if (cmp0(op, a)) next = lbl.get(((JumpInsnNode) n).label);
                        break;
                    }
                    case IF_ICMPEQ: case IF_ICMPNE: case IF_ICMPLT: case IF_ICMPGE: case IF_ICMPGT: case IF_ICMPLE: {
                        int b = asInt(st.pop()), a = asInt(st.pop());
                        if (icmp(op, a, b)) next = lbl.get(((JumpInsnNode) n).label);
                        break;
                    }
                    case IF_ACMPEQ: case IF_ACMPNE: {
                        Object b = st.pop(), a = st.pop();
                        boolean eq = (a == b) || (a == NULLV && b == NULLV);
                        if ((op == IF_ACMPEQ) == eq) next = lbl.get(((JumpInsnNode) n).label);
                        break;
                    }
                    case IFNULL: { Object a = st.pop(); if (a == NULLV || a == null) next = lbl.get(((JumpInsnNode) n).label); break; }
                    case IFNONNULL: { Object a = st.pop(); if (!(a == NULLV || a == null)) next = lbl.get(((JumpInsnNode) n).label); break; }
                    case GOTO: next = lbl.get(((JumpInsnNode) n).label); break;
                    case TABLESWITCH: {
                        TableSwitchInsnNode ts = (TableSwitchInsnNode) n;
                        int k = asInt(st.pop());
                        next = (k >= ts.min && k <= ts.max) ? lbl.get(ts.labels.get(k - ts.min)) : lbl.get(ts.dflt);
                        break;
                    }
                    case LOOKUPSWITCH: {
                        LookupSwitchInsnNode ls = (LookupSwitchInsnNode) n;
                        int k = asInt(st.pop());
                        int idx = ls.keys.indexOf(k);
                        next = lbl.get(idx >= 0 ? ls.labels.get(idx) : ls.dflt);
                        break;
                    }
                    case IRETURN: case FRETURN: case ARETURN: return st.pop();
                    case LRETURN: case DRETURN: return st.pop();
                    case RETURN: return null;
                    case GETSTATIC: {
                        FieldInsnNode fi = (FieldInsnNode) n;
                        if (fi.owner.equals("java/nio/charset/StandardCharsets")) {
                            SimObj cs = new SimObj("charset");
                            cs.f.put("name", new SimStr(fi.name));
                            st.push(cs);
                            break;
                        }
                        if (!fi.owner.equals(cn.name)) throw new Stop("getstatic " + fi.owner + "." + fi.name);
                        st.push(statics.getOrDefault(fi.name, defaultVal(fi.desc)));
                        break;
                    }
                    case PUTSTATIC: {
                        FieldInsnNode fi = (FieldInsnNode) n;
                        if (!fi.owner.equals(cn.name)) throw new Stop("putstatic " + fi.owner);
                        statics.put(fi.name, st.pop());
                        break;
                    }
                    case GETFIELD: {
                        FieldInsnNode fi = (FieldInsnNode) n;
                        Object o = st.pop();
                        st.push(o instanceof SimObj ? ((SimObj) o).f.getOrDefault(fi.name, defaultVal(fi.desc)) : NULLV);
                        break;
                    }
                    case PUTFIELD: {
                        FieldInsnNode fi = (FieldInsnNode) n;
                        Object v = st.pop(), o = st.pop();
                        if (o instanceof SimObj) ((SimObj) o).f.put(fi.name, v);
                        break;
                    }
                    case INVOKEVIRTUAL: case INVOKESPECIAL: case INVOKESTATIC: case INVOKEINTERFACE: {
                        MethodInsnNode mi = (MethodInsnNode) n;
                        Type[] at2 = Type.getArgumentTypes(mi.desc);
                        Object[] a = new Object[at2.length];
                        for (int i = at2.length - 1; i >= 0; i--) a[i] = st.pop();
                        Object recv = null;
                        if (op != INVOKESTATIC) recv = st.pop();
                        Object r;
                        MethodNode self = methods.get(mi.name + mi.desc);
                        boolean isAes = aesDecName != null && mi.name.equals(aesDecName) && mi.desc.equals(aesDecDesc);
                        if (!isAes && op == INVOKESTATIC && mi.owner.equals(cn.name) && self != null) {
                            r = run(self, a);
                        } else if (!isAes && op == INVOKESPECIAL && mi.owner.equals(cn.name) && self != null) {
                            Object[] withRecv = new Object[a.length + 1];
                            withRecv[0] = recv;
                            System.arraycopy(a, 0, withRecv, 1, a.length);
                            r = run(self, withRecv);
                        } else {
                            Object[] args2;
                            if (op == INVOKESTATIC) {
                                args2 = a;
                            } else {
                                args2 = new Object[a.length + 1];
                                args2[0] = recv;
                                System.arraycopy(a, 0, args2, 1, a.length);
                            }
                            r = invokeNative(op, mi.owner, mi.name, mi.desc, args2);
                        }
                        Type rt = Type.getReturnType(mi.desc);
                        if (rt.getSort() != Type.VOID) st.push(r);
                        break;
                    }
                    case INVOKEDYNAMIC: throw new Stop("invokedynamic in-body");
                    case NEW: {
                        String tn = ((TypeInsnNode) n).desc;
                        st.push(tn.equals("java/lang/String") ? new SimStr(new int[0]) : new SimObj(tn));
                        break;
                    }
                    case NEWARRAY: {
                        int len = asInt(st.pop());
                        int t = ((IntInsnNode) n).operand;
                        char tc = (t == 8 ? 'B' : t == 5 ? 'C' : t == 10 ? 'I' : t == 11 ? 'J' : 'I');
                        st.push(new SimArr(tc, len));
                        break;
                    }
                    case ANEWARRAY: { int len = asInt(st.pop()); st.push(new SimArr('L', len)); break; }
                    case ARRAYLENGTH: {
                        Object a = st.pop();
                        st.push(a instanceof SimArr ? ((SimArr) a).v.length : (a instanceof SimStr ? ((SimStr) a).u.length : 0));
                        break;
                    }
                    case ATHROW: throw new JThrow(st.pop());
                    case CHECKCAST: break;
                    case INSTANCEOF: { Object o = st.pop(); st.push((o != NULLV && o != null) ? 1 : 0); break; }
                    case MONITORENTER: case MONITOREXIT: st.pop(); break;
                    case MULTIANEWARRAY: {
                        MultiANewArrayInsnNode ma = (MultiANewArrayInsnNode) n;
                        for (int i = 0; i < ma.dims; i++) st.pop();
                        st.push(new SimArr('L', 0));
                        break;
                    }
                    default: throw new Stop("op " + op);
                }
            } catch (JThrow ex) {
                Integer h = handler(m, pc, lbl);
                if (h == null) throw ex;
                st.clear();
                st.push(ex.o);
                next = h;
            }
            pc = next;
        }
    }

    private Integer handler(MethodNode m, int pc, Map<LabelNode, Integer> lbl) {
        if (m.tryCatchBlocks == null) return null;
        for (TryCatchBlockNode t : m.tryCatchBlocks) {
            int s = lbl.get(t.start), e = lbl.get(t.end);
            if (pc >= s && pc < e) return lbl.get(t.handler);
        }
        return null;
    }

    private Object invokeNative(int op, String owner, String name, String desc, Object[] a) {
        if (aesDecName != null && name.equals(aesDecName) && desc.equals(aesDecDesc)) {
            try {
                byte[] iv = toBytes((SimArr) a[0]);
                String pw = ((SimStr) a[1]).str();
                String b64 = ((SimStr) a[2]).str();
                return new SimStr(Crypto.aesDecrypt(iv, pw, b64));
            } catch (Exception e) {
                throw new Stop("aes: " + e);
            }
        }
        if (name.equals("findStatic") || name.equals("findVirtual") || name.equals("findSpecial")) {
            String which = name.equals("findStatic") ? "static" : name.equals("findVirtual") ? "virtual" : "special";
            throw new FindX(which, clsName(a[1]), simStr(a[2]), mtDesc(a[3]));
        }
        if (name.equals("findConstructor")) throw new FindX("ctor", clsName(a[1]), "<init>", mtDesc(a[2]));
        if (name.equals("lookupClass") && a[0] instanceof SimObj) {
            SimObj c = new SimObj("java/lang/Class");
            Object nm = ((SimObj) a[0]).f.get("name");
            c.f.put("name", nm != null ? nm : new SimStr(cn.name));
            return c;
        }
        if (name.equals("getName") && a[0] instanceof SimObj && ((SimObj) a[0]).cls.equals("java/lang/Class")) {
            Object nm = ((SimObj) a[0]).f.get("name");
            return new SimStr(nm != null ? simStr(nm).replace('/', '.') : cn.name.replace('/', '.'));
        }
        if (name.equals("toString") && desc.equals("()Ljava/lang/String;") && a[0] instanceof SimObj) {
            SimObj o = (SimObj) a[0];
            if (o.cls.contains("Lookup")) return new SimStr(cn.name);
            if (o.cls.equals("java/lang/Class")) return new SimStr(str(o.f.get("name")));
        }
        String k = owner + "." + name + desc;
        switch (k) {
            case "java/lang/String.length()I": return ((SimStr) a[0]).u.length;
            case "java/lang/String.toCharArray()[C": {
                int[] u = ((SimStr) a[0]).u;
                SimArr r = new SimArr('C', u.length);
                for (int i = 0; i < u.length; i++) r.v[i] = u[i];
                return r;
            }
            case "java/lang/String.intern()Ljava/lang/String;": return a[0];
            case "java/lang/String.hashCode()I": {
                int h = 0;
                for (int c : ((SimStr) a[0]).u) h = 31 * h + c;
                return h;
            }
            case "java/lang/String.charAt(I)C": return ((SimStr) a[0]).u[asInt(a[1])];
            case "java/lang/String.<init>([C)V": { ((SimStr) a[0]).u = fromCharArr((SimArr) a[1]); return null; }
            case "java/lang/String.<init>([B)V": {
                ((SimStr) a[0]).u = new SimStr(new String(toBytes((SimArr) a[1]), java.nio.charset.StandardCharsets.UTF_8)).u;
                return null;
            }
            case "java/lang/String.<init>([BLjava/nio/charset/Charset;)V":
            case "java/lang/String.<init>([BLjava/lang/String;)V": {
                ((SimStr) a[0]).u = new SimStr(new String(toBytes((SimArr) a[1]), charset(a[2]))).u;
                return null;
            }
            case "java/lang/String.getBytes()[B": {
                byte[] bs = ((SimStr) a[0]).str().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                SimArr r = new SimArr('B', bs.length);
                for (int i = 0; i < bs.length; i++) r.v[i] = (int) bs[i];
                return r;
            }
            case "java/lang/String.getBytes(Ljava/nio/charset/Charset;)[B":
            case "java/lang/String.getBytes(Ljava/lang/String;)[B": {
                byte[] bs = ((SimStr) a[0]).str().getBytes(charset(a[1]));
                SimArr r = new SimArr('B', bs.length);
                for (int i = 0; i < bs.length; i++) r.v[i] = (int) bs[i];
                return r;
            }
            case "java/lang/String.valueOf([C)Ljava/lang/String;": return new SimStr(fromCharArr((SimArr) a[0]));
            case "java/lang/String.substring(II)Ljava/lang/String;": return sub((SimStr) a[0], asInt(a[1]), asInt(a[2]));
            case "java/lang/String.substring(I)Ljava/lang/String;": return sub((SimStr) a[0], asInt(a[1]), ((SimStr) a[0]).u.length);
            case "java/lang/Object.<init>()V": return null;
            case "java/lang/StringBuilder.<init>()V": ((SimObj) a[0]).f.put("sb", new StringBuilder()); return null;
            case "java/lang/StringBuilder.toString()Ljava/lang/String;":
                return new SimStr(((StringBuilder) ((SimObj) a[0]).f.get("sb")).toString());
            case "java/util/Base64.getDecoder()Ljava/util/Base64$Decoder;": return new SimObj("b64d");
            case "java/lang/Class.getClassLoader()Ljava/lang/ClassLoader;": return new SimObj("loader");
            case "java/lang/Integer.intValue()I": return asInt(((SimObj) a[0]).f.get("v"));
        }
        if (owner.equals("java/lang/StringBuilder") && (name.equals("append") || name.equals("<init>"))) {
            SimObj o = (SimObj) a[0];
            StringBuilder sb = (StringBuilder) o.f.get("sb");
            if (sb == null) { sb = new StringBuilder(); o.f.put("sb", sb); }
            if (a.length > 1) {
                Object x = a[1];
                String ptype = desc.substring(1, desc.indexOf(')'));
                if (ptype.equals("C")) sb.append((char) asInt(x));
                else if (ptype.equals("I") || ptype.equals("S") || ptype.equals("B")) sb.append(asInt(x));
                else if (ptype.equals("J")) sb.append(asLong(x));
                else if (ptype.equals("Z")) sb.append(asInt(x) != 0);
                else if (x instanceof SimStr) sb.append(((SimStr) x).str());
                else if (x == NULLV || x == null) sb.append("null");
                else sb.append(String.valueOf(x));
            }
            return name.equals("<init>") ? null : a[0];
        }
        if (owner.equals("java/util/Base64$Decoder") && name.equals("decode")) {
            byte[] raw = (a[1] instanceof SimStr) ? Base64.getDecoder().decode(((SimStr) a[1]).str())
                                                  : Base64.getDecoder().decode(toBytes((SimArr) a[1]));
            SimArr r = new SimArr('B', raw.length);
            for (int i = 0; i < raw.length; i++) r.v[i] = (int) raw[i];
            return r;
        }
        if (owner.equals("java/lang/Integer") && name.equals("valueOf")) {
            SimObj o = new SimObj("java/lang/Integer");
            o.f.put("v", asInt(a[0]));
            return o;
        }
        if (owner.equals("java/lang/Long") && name.equals("valueOf")) {
            SimObj o = new SimObj("java/lang/Long");
            o.f.put("v", a[0]);
            return o;
        }
        if (owner.equals("java/lang/Integer") && name.equals("parseInt")) {
            String t = ((SimStr) a[0]).str();
            int rad = a.length > 1 ? asInt(a[1]) : 10;
            return (int) Long.parseLong(t, rad);
        }
        if (owner.equals("java/lang/Math") && name.equals("min")) return Math.min(asInt(a[0]), asInt(a[1]));
        if (owner.equals("java/lang/Math") && name.equals("max")) return Math.max(asInt(a[0]), asInt(a[1]));
        if (owner.equals("java/lang/Class") && name.equals("forName")) {
            SimObj o = new SimObj("java/lang/Class");
            o.f.put("name", simStr(a[0]));
            return o;
        }
        if (name.equals("fromMethodDescriptorString")) {
            SimObj o = new SimObj("mt");
            o.f.put("desc", simStr(a[0]));
            return o;
        }
        if (name.equals("split")) {
            String txt = ((SimStr) a[0]).str();
            String sep = ((SimStr) a[1]).str();
            int limit = a.length > 2 ? asInt(a[2]) : 0;
            String[] parts = txt.split(java.util.regex.Pattern.quote(sep), limit > 0 ? limit : -1);
            if (limit == 0) {
                int end = parts.length;
                while (end > 0 && parts[end - 1].isEmpty()) end--;
                parts = Arrays.copyOf(parts, end);
            }
            SimArr r = new SimArr('L', parts.length);
            for (int i = 0; i < parts.length; i++) r.v[i] = new SimStr(parts[i]);
            return r;
        }
        if (owner.equals("java/lang/System") && name.equals("arraycopy")) {
            SimArr src = (SimArr) a[0];
            int sp = asInt(a[1]);
            SimArr dst = (SimArr) a[2];
            int dp = asInt(a[3]);
            int ln = asInt(a[4]);
            System.arraycopy(src.v, sp, dst.v, dp, ln);
            return null;
        }
        throw new Stop("native " + k);
    }

    static final Object NULLV = new Object();

    private static Object defaultVal(String desc) {
        char c = desc.charAt(0);
        if (c == 'I' || c == 'Z' || c == 'B' || c == 'S' || c == 'C') return 0;
        if (c == 'J') return 0L;
        if (c == 'F' || c == 'D') return 0.0;
        return NULLV;
    }

    private static int asInt(Object o) {
        if (o instanceof Integer) return (Integer) o;
        if (o instanceof Long) return (int) (long) (Long) o;
        if (o == null || o == NULLV) return 0;
        if (o instanceof Double) return (int) (double) (Double) o;
        throw new Stop("asInt " + o);
    }

    private static long asLong(Object o) {
        if (o instanceof Long) return (Long) o;
        if (o instanceof Integer) return (Integer) o;
        if (o instanceof Double) return (long) (double) (Double) o;
        throw new Stop("asLong");
    }

    private static double asDouble(Object o) {
        if (o instanceof Double) return (Double) o;
        if (o instanceof Integer) return (Integer) o;
        if (o instanceof Long) return (Long) o;
        throw new Stop("asDouble");
    }

    private static int iop(int op, int a, int b) {
        switch (op) {
            case IADD: return a + b;
            case ISUB: return a - b;
            case IMUL: return a * b;
            case IDIV: if (b == 0) throw new JThrow("div0"); return a / b;
            case IREM: if (b == 0) throw new JThrow("div0"); return a % b;
            case ISHL: return a << (b & 31);
            case ISHR: return a >> (b & 31);
            case IUSHR: return a >>> (b & 31);
            case IAND: return a & b;
            case IOR: return a | b;
            case IXOR: return a ^ b;
        }
        throw new Stop("iop");
    }

    private static long lop(int op, long a, long b) {
        switch (op) {
            case LADD: return a + b;
            case LSUB: return a - b;
            case LMUL: return a * b;
            case LDIV: return a / b;
            case LREM: return a % b;
            case LSHL: return a << ((int) b & 63);
            case LSHR: return a >> ((int) b & 63);
            case LUSHR: return a >>> ((int) b & 63);
            case LAND: return a & b;
            case LOR: return a | b;
            case LXOR: return a ^ b;
        }
        throw new Stop("lop");
    }

    private static boolean cmp0(int op, int a) {
        switch (op) {
            case IFEQ: return a == 0;
            case IFNE: return a != 0;
            case IFLT: return a < 0;
            case IFGE: return a >= 0;
            case IFGT: return a > 0;
            case IFLE: return a <= 0;
        }
        return false;
    }

    private static boolean icmp(int op, int a, int b) {
        switch (op) {
            case IF_ICMPEQ: return a == b;
            case IF_ICMPNE: return a != b;
            case IF_ICMPLT: return a < b;
            case IF_ICMPGE: return a >= b;
            case IF_ICMPGT: return a > b;
            case IF_ICMPLE: return a <= b;
        }
        return false;
    }

    private static byte[] toBytes(SimArr a) {
        byte[] b = new byte[a.v.length];
        for (int i = 0; i < b.length; i++) b[i] = (byte) asInt(a.v[i]);
        return b;
    }

    private static int[] fromCharArr(SimArr a) {
        int[] u = new int[a.v.length];
        for (int i = 0; i < u.length; i++) u[i] = asInt(a.v[i]) & 0xffff;
        return u;
    }

    private static SimStr sub(SimStr s, int a, int b) {
        return new SimStr(Arrays.copyOfRange(s.u, a, b));
    }

    private static java.nio.charset.Charset charset(Object o) {
        String nm = "UTF-8";
        if (o instanceof SimObj) {
            Object x = ((SimObj) o).f.get("name");
            if (x != null) nm = simStr(x);
        } else if (o instanceof SimStr) {
            nm = ((SimStr) o).str();
        }
        switch (nm) {
            case "ISO_8859_1": case "ISO-8859-1": return java.nio.charset.StandardCharsets.ISO_8859_1;
            case "US_ASCII": case "US-ASCII": return java.nio.charset.StandardCharsets.US_ASCII;
            case "UTF_16": case "UTF-16": return java.nio.charset.StandardCharsets.UTF_16;
            default: return java.nio.charset.StandardCharsets.UTF_8;
        }
    }

    private static String simStr(Object o) {
        return o instanceof SimStr ? ((SimStr) o).str() : String.valueOf(o);
    }

    private static String clsName(Object o) {
        if (o instanceof SimObj) {
            Object nm = ((SimObj) o).f.get("name");
            return nm == null ? null : simStr(nm);
        }
        return null;
    }

    private static String mtDesc(Object o) {
        if (o instanceof SimObj) {
            Object d = ((SimObj) o).f.get("desc");
            return d == null ? null : simStr(d);
        }
        return null;
    }

    private static String str(Object o) {
        return o == null ? null : simStr(o);
    }
}
