package qp.deob.passes;

import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import qp.deob.ClassFacts;
import qp.deob.Insns;
import java.util.*;

public final class SyntheticMemberRemovalPass implements DeobPass, Opcodes {
    public String id() { return "synthetic"; }
    public String label() { return "SyntheticRemoval"; }
    public String desc() { return "delete unreachable decryptor/linker/pool synthetics + clinit init"; }

    private static final String SEP = "\u0000";

    public PassResult apply(ClassNode cn, ClassFacts facts) {
        PassResult r = new PassResult();
        if (facts == null || !facts.ok) return r;

        Set<String> synMethods = facts.syntheticMethods;
        Set<String> synFields = facts.syntheticFields;

        Set<String> liveMethods = new HashSet<>();
        Set<String> liveFields = new HashSet<>();
        computeLive(cn, synMethods, synFields, liveMethods, liveFields);

        Set<String> deadFields = new HashSet<>(synFields);
        deadFields.removeAll(liveFields);

        MethodNode clinit = method(cn, "<clinit>", "()V");
        if (clinit != null && clinit.instructions != null) {
            int cc = 0;
            for (AbstractInsnNode n : clinit.instructions.toArray()) {
                if (!(n instanceof MethodInsnNode)) continue;
                MethodInsnNode mi = (MethodInsnNode) n;
                String key = mi.name + SEP + mi.desc;
                if (mi.owner.equals(cn.name) && synMethods.contains(key) && !liveMethods.contains(key)
                    && Insns.argCount(mi.desc) == 0 && mi.desc.endsWith(")V")) {
                    clinit.instructions.remove(n);
                    cc++;
                }
            }
            r.add("clinitCallsRemoved", cc);
            r.add("clinitInitRemoved", removeSpecPrefix(cn, clinit, deadFields));
            dropEmptyClinit(cn, clinit);
        }

        int mrem = 0;
        for (Iterator<MethodNode> it = cn.methods.iterator(); it.hasNext(); ) {
            MethodNode mn = it.next();
            String key = mn.name + SEP + mn.desc;
            if (synMethods.contains(key) && !liveMethods.contains(key)) {
                it.remove();
                mrem++;
                r.detail(cn.name + " - method " + mn.name + mn.desc);
            }
        }
        r.add("methodsRemoved", mrem);
        if (!liveMethods.isEmpty()) r.add("methodsKeptReferenced", liveMethods.size());

        int frem = 0;
        for (Iterator<FieldNode> it = cn.fields.iterator(); it.hasNext(); ) {
            FieldNode f = it.next();
            if (deadFields.contains(f.name) && !fieldReferenced(cn, f.name)) {
                it.remove();
                frem++;
                r.detail(cn.name + " - field " + f.name);
            }
        }
        r.add("fieldsRemoved", frem);
        if (!liveFields.isEmpty()) r.add("fieldsKeptReferenced", liveFields.size());
        return r;
    }

    private void computeLive(ClassNode cn, Set<String> synMethods, Set<String> synFields,
                             Set<String> liveMethods, Set<String> liveFields) {
        Map<String, MethodNode> byKey = new HashMap<>();
        for (MethodNode mn : cn.methods) byKey.put(mn.name + SEP + mn.desc, mn);

        Deque<String> work = new ArrayDeque<>();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            String key = mn.name + SEP + mn.desc;
            if (synMethods.contains(key) || mn.name.equals("<clinit>")) continue;
            for (AbstractInsnNode n : mn.instructions.toArray()) {
                String mref = methodRef(cn, n);
                if (mref != null && synMethods.contains(mref) && liveMethods.add(mref)) work.push(mref);
                String fref = fieldRef(cn, n);
                if (fref != null && synFields.contains(fref)) liveFields.add(fref);
            }
        }
        boolean changed = true;
        while (changed || !work.isEmpty()) {
            changed = false;
            while (!work.isEmpty()) {
                MethodNode mn = byKey.get(work.pop());
                if (mn == null || mn.instructions == null) continue;
                for (AbstractInsnNode n : mn.instructions.toArray()) {
                    String mref = methodRef(cn, n);
                    if (mref != null && synMethods.contains(mref) && liveMethods.add(mref)) work.push(mref);
                    String fref = fieldRef(cn, n);
                    if (fref != null && synFields.contains(fref)) liveFields.add(fref);
                }
            }
            for (MethodNode mn : cn.methods) {
                String key = mn.name + SEP + mn.desc;
                if (!synMethods.contains(key) || liveMethods.contains(key) || mn.instructions == null) continue;
                if (writesAny(mn, cn, liveFields)) { liveMethods.add(key); work.push(key); changed = true; }
            }
        }
    }

    private static String methodRef(ClassNode cn, AbstractInsnNode n) {
        if (n instanceof MethodInsnNode) {
            MethodInsnNode mi = (MethodInsnNode) n;
            if (mi.owner.equals(cn.name)) return mi.name + SEP + mi.desc;
        } else if (n instanceof InvokeDynamicInsnNode) {
            Handle h = ((InvokeDynamicInsnNode) n).bsm;
            if (h != null && h.getOwner().equals(cn.name)) return h.getName() + SEP + h.getDesc();
        }
        return null;
    }

    private static String fieldRef(ClassNode cn, AbstractInsnNode n) {
        if (n instanceof FieldInsnNode) {
            FieldInsnNode fi = (FieldInsnNode) n;
            if (fi.owner.equals(cn.name)) return fi.name;
        }
        return null;
    }

    private static boolean writesAny(MethodNode mn, ClassNode cn, Set<String> fields) {
        if (fields.isEmpty()) return false;
        for (AbstractInsnNode n : mn.instructions.toArray())
            if (n.getOpcode() == PUTSTATIC && n instanceof FieldInsnNode) {
                FieldInsnNode fi = (FieldInsnNode) n;
                if (fi.owner.equals(cn.name) && fields.contains(fi.name)) return true;
            }
        return false;
    }

    private int removeSpecPrefix(ClassNode cn, MethodNode clinit, Set<String> deadFields) {
        AbstractInsnNode[] arr = clinit.instructions.toArray();
        int last = -1;
        for (int i = 0; i < arr.length; i++)
            if (arr[i] instanceof FieldInsnNode) {
                FieldInsnNode fi = (FieldInsnNode) arr[i];
                if (fi.owner.equals(cn.name) && deadFields.contains(fi.name)) last = i;
            }
        if (last < 0) return 0;
        for (int i = 0; i <= last; i++) {
            AbstractInsnNode n = arr[i];
            if (n.getOpcode() < 0) continue;
            if (n instanceof LabelNode || n instanceof JumpInsnNode
                || n instanceof TableSwitchInsnNode || n instanceof LookupSwitchInsnNode) return 0;
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode) return 0;
            if (n instanceof FieldInsnNode) {
                FieldInsnNode fi = (FieldInsnNode) n;
                if (!(fi.owner.equals(cn.name) && deadFields.contains(fi.name))) return 0;
            }
        }
        int c = 0;
        for (int i = 0; i <= last; i++) {
            if (arr[i].getOpcode() < 0) continue;
            clinit.instructions.remove(arr[i]);
            c++;
        }
        return c;
    }

    private void dropEmptyClinit(ClassNode cn, MethodNode clinit) {
        for (AbstractInsnNode n : clinit.instructions.toArray()) {
            if (n.getOpcode() < 0) continue;
            if (n.getOpcode() == RETURN) continue;
            return;
        }
        cn.methods.remove(clinit);
    }

    private boolean fieldReferenced(ClassNode cn, String field) {
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            for (AbstractInsnNode n : mn.instructions.toArray())
                if (n instanceof FieldInsnNode) {
                    FieldInsnNode fi = (FieldInsnNode) n;
                    if (fi.owner.equals(cn.name) && fi.name.equals(field)) return true;
                }
        }
        return false;
    }

    private static MethodNode method(ClassNode cn, String name, String desc) {
        for (MethodNode mn : cn.methods)
            if (mn.name.equals(name) && mn.desc.equals(desc)) return mn;
        return null;
    }

    public String describe(PassResult r) {
        int methods = r.count("methodsRemoved");
        int fields = r.count("fieldsRemoved");
        List<String> parts = new ArrayList<>();
        if (methods > 0) parts.add(methods + " methods");
        if (fields > 0) parts.add(fields + " fields");
        return parts.isEmpty() ? "" : "removed " + String.join(", ", parts);
    }
}
