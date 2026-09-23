package qp.deob.passes;

import org.objectweb.asm.tree.ClassNode;
import qp.deob.ClassFacts;

public interface DeobPass {
    String id();
    String label();
    String desc();
    PassResult apply(ClassNode cn, ClassFacts facts);
    String describe(PassResult r);
}
