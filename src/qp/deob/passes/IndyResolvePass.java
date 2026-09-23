package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import qp.deob.Env;

public final class IndyResolvePass implements DeobPass, Opcodes {
    private final Env env;

    public IndyResolvePass(Env env) { this.env = env; }

    public String id() { return "indy"; }
    public String label() { return "IndyResolve"; }
    public String desc() { return "resolve invokedynamic linker sites to real invoke*"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        if (facts == null || !facts.ok) return r;
        for (ClassFacts.IndySite is : facts.indySites) {
            if (!(is.node instanceof InvokeDynamicInsnNode)) { r.add("indySkipped", 1); continue; }
            MethodNode mn = methodOf(cn, is.method, is.desc);
            if (mn == null) { r.add("indySkipped", 1); continue; }
            boolean itf = env != null && env.isInterface(is.owner);
            int opcode;
            String name = is.name;
            switch (is.kind) {
                case "static":  opcode = INVOKESTATIC; break;
                case "special": opcode = INVOKESPECIAL; break;
                case "ctor":    opcode = INVOKESPECIAL; name = "<init>"; itf = false; break;
                case "virtual":
                default:        opcode = itf ? INVOKEINTERFACE : INVOKEVIRTUAL; break;
            }
            if (opcode == INVOKEVIRTUAL) itf = false;
            MethodInsnNode call = new MethodInsnNode(opcode, is.owner, name, is.tdesc, itf);
            mn.instructions.set(is.node, call);
            r.add("indyResolved", 1);
            r.detail(cn.name + "#" + is.method + " @" + is.ordinal + " -> " + opName(opcode) + " "
                     + is.owner + "." + name + is.tdesc);
        }
        return r;
    }

    private static String opName(int op) {
        switch (op) {
            case INVOKESTATIC: return "invokestatic";
            case INVOKEVIRTUAL: return "invokevirtual";
            case INVOKESPECIAL: return "invokespecial";
            case INVOKEINTERFACE: return "invokeinterface";
            default: return "invoke?";
        }
    }

    private static MethodNode methodOf(ClassNode cn, String name, String desc) {
        for (MethodNode mn : cn.methods)
            if (mn.name.equals(name) && mn.desc.equals(desc)) return mn;
        return null;
    }

    public String describe(PassResult r) {
        int n = r.count("indyResolved");
        return n == 0 ? "" : "resolved " + n + " calls";
    }
}
