package qp.deob.passes;

import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import java.util.ArrayList;
import java.util.List;

public final class InfoStripNotePass implements DeobPass {
    public String id() { return "infostrip"; }
    public String label() { return "InfoStrip"; }
    public String desc() { return "clear residual line numbers + local variable tables (lossy)"; }

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions != null) {
                for (AbstractInsnNode n : mn.instructions.toArray()) {
                    if (n instanceof LineNumberNode) {
                        mn.instructions.remove(n);
                        r.add("lineNumbersStripped", 1);
                    }
                }
            }
            if (mn.localVariables != null && !mn.localVariables.isEmpty()) {
                r.add("localVarsCleared", mn.localVariables.size());
                mn.localVariables.clear();
            }
        }
        return r;
    }

    public String describe(PassResult r) {
        int lines = r.count("lineNumbersStripped");
        int vars = r.count("localVarsCleared");
        List<String> parts = new ArrayList<>();
        if (lines > 0) parts.add("stripped " + lines + " line numbers");
        if (vars > 0) parts.add("cleared " + vars + " local vars");
        return String.join(", ", parts);
    }
}
