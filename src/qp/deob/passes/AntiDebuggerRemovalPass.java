package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;

public final class AntiDebuggerRemovalPass implements DeobPass, Opcodes {
    public String id() { return "antidebugger"; }
    public String label() { return "AntiDebugger"; }
    public String desc() { return "neutralise injected getInputArguments jdwp/agent anti-debug methods"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        int n = 0;
        for (MethodNode mn : cn.methods) {
            if (!mn.desc.endsWith(")V") || !isAntiDebug(mn)) continue;
            mn.instructions.clear();
            mn.instructions.add(new InsnNode(RETURN));
            if (mn.tryCatchBlocks != null) mn.tryCatchBlocks.clear();
            if (mn.localVariables != null) mn.localVariables.clear();
            mn.maxStack = 0;
            n++;
            r.detail(cn.name + " - neutralised anti-debug " + mn.name);
        }
        r.add("antiDebugNeutralised", n);
        return r;
    }

    private boolean isAntiDebug(MethodNode mn) {
        if (mn.instructions == null) return false;
        boolean rmx = false, inArgs = false, marker = false;
        for (AbstractInsnNode n : mn.instructions.toArray()) {
            if (n instanceof MethodInsnNode) {
                MethodInsnNode mi = (MethodInsnNode) n;
                if (mi.owner.equals("java/lang/management/ManagementFactory") && mi.name.equals("getRuntimeMXBean")) rmx = true;
                if (mi.owner.equals("java/lang/management/RuntimeMXBean") && mi.name.equals("getInputArguments")) inArgs = true;
            } else if (n instanceof LdcInsnNode && ((LdcInsnNode) n).cst instanceof String) {
                String s = (String) ((LdcInsnNode) n).cst;
                if (s.contains("javaagent") || s.contains("jdwp") || s.contains("-Xdebug") || s.contains("-agentlib")) marker = true;
            }
        }
        return rmx && inArgs && marker;
    }

    public String describe(PassResult r) {
        int m = r.count("antiDebugNeutralised");
        return m == 0 ? "" : "neutralised " + m + " anti-debug method(s)";
    }
}
