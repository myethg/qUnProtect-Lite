package qp.deob.passes;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;

public final class AccessCleanPass implements DeobPass, Opcodes {
    public String id() { return "accessclean"; }
    public String label() { return "AccessClean"; }
    public String desc() { return "clear obfuscator-sprayed STRICT/SYNTHETIC/BRIDGE access flags"; }

    private static final int JUNK = ACC_STRICT | ACC_SYNTHETIC | ACC_BRIDGE;

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        int c = 0;
        if ((cn.access & ACC_SYNTHETIC) != 0) { cn.access &= ~ACC_SYNTHETIC; c++; }
        for (MethodNode mn : cn.methods) {
            if (facts != null && facts.isSyntheticMethod(mn.name, mn.desc)) continue;
            if ((mn.access & JUNK) != 0) { mn.access &= ~JUNK; c++; }
        }
        for (FieldNode fn : cn.fields)
            if ((fn.access & ACC_SYNTHETIC) != 0) { fn.access &= ~ACC_SYNTHETIC; c++; }
        r.add("accessCleaned", c);
        return r;
    }

    public String describe(PassResult r) {
        int n = r.count("accessCleaned");
        return n == 0 ? "" : "cleaned " + n + " access flags";
    }
}
