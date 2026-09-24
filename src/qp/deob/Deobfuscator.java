package qp.deob;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.util.CheckClassAdapter;
import org.objectweb.asm.util.TraceClassVisitor;

import qp.deob.passes.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import java.util.zip.*;

public final class Deobfuscator {

    static final String NAME = "qUnProtect Lite";
    static final String VERSION = "1.0";
    private static final int TAG_WIDTH = 18;

    private boolean useFacts = true;
    private boolean verbose = false;
    private String stagesDir = null;
    private Set<String> onlyIds = null;
    private String stopAfter = null;

    private List<DeobPass> pipeline;
    private Env env;

    private int classCount, classFullyResolved, classPartial, classFailed, classValid, classInvalid;
    private final LinkedHashMap<String, Integer> agg = new LinkedHashMap<>();

    private final PrintStream log = System.err;

    public static void main(String[] args) throws Exception {
        new Deobfuscator().cli(args);
    }

    void cli(String[] args) throws Exception {
        boolean noColor = false;
        for (String a : args) if (a.equals("--no-color")) noColor = true;
        Ansi.setEnabled(!noColor && System.console() != null);

        List<String> pos = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-h": case "--help": help(); return;
                case "--passes": listPasses(); return;
                case "-v": case "--verbose": verbose = true; break;
                case "--no-facts": useFacts = false; break;
                case "--no-color": break;
                case "--only": onlyIds = new LinkedHashSet<>(Arrays.asList(args[++i].split(","))); break;
                case "--stop-after": stopAfter = args[++i]; break;
                case "--stages": stagesDir = args[++i]; break;
                case "--print": printClass(args[++i]); return;
                default: pos.add(a);
            }
        }
        if (pos.size() < 2) { help(); System.exit(2); return; }
        run(pos.get(0), pos.get(1));
    }

    private final Set<DeobPass> factPasses = new HashSet<>();

    private void buildPipeline() {
        pipeline = new ArrayList<>();
        pipeline.add(new PolymorphStripPass());
        pipeline.add(new NumberFoldPass());
        pipeline.add(new BogusSwitchCollapsePass());
        pipeline.add(new FakeTryCatchRemovalPass());
        pipeline.add(new OpaquePredicateCollapsePass());
        pipeline.add(new ReverseJumpUninvertPass());
        pipeline.add(new UselessCheckCastPass());
        pipeline.add(new DeadCodePass());
        pipeline.add(new FakeTryCatchRemovalPass());
        pipeline.add(new DeadCodePass());
        pipeline.add(new PolymorphStripPass());
        addFactPass(new StringDecryptPass());
        addFactPass(new IndyResolvePass(env));
        addFactPass(new AntiDebuggerRemovalPass());
        addFactPass(new SyntheticMemberRemovalPass());
        addFactPass(new AccessCleanPass());
        addFactPass(new InfoStripNotePass());
    }

    private void addFactPass(DeobPass p) {
        pipeline.add(p);
        factPasses.add(p);
    }

    private ClassFacts boundFacts(ClassNode cn, List<String> report) {
        ClassFacts facts = obtainFacts(cn);
        List<String> bindReport = new ArrayList<>();
        if (facts.ok) facts.bind(cn, bindReport);
        for (String s : bindReport) report.add(cn.name + ": " + s);
        return facts;
    }

    void run(String in, String out) throws Exception {
        banner();

        Map<String, byte[]> input = readAll(in);
        Map<String, byte[]> passthrough = new LinkedHashMap<>();
        Map<String, byte[]> classBytes = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : input.entrySet()) {
            byte[] b = e.getValue();
            if (isClass(b)) classBytes.put(readInternalName(b), b);
            else passthrough.put(e.getKey(), b);
        }

        List<ClassNode> nodes = new ArrayList<>();
        Map<String, ClassNode> nodeByName = new LinkedHashMap<>();
        Map<String, byte[]> origByName = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : classBytes.entrySet()) {
            ClassNode cn = new ClassNode();
            new ClassReader(e.getValue()).accept(cn, ClassReader.SKIP_FRAMES);
            nodes.add(cn);
            nodeByName.put(cn.name, cn);
            origByName.put(cn.name, e.getValue());
        }
        env = new Env(nodes);
        buildPipeline();

        Map<String, byte[]> output = new LinkedHashMap<>(passthrough);
        List<String> report = new ArrayList<>();

        if (stagesDir != null) {
            dumpStage(0, "input", origByName);
            runStaged(nodes, report);
        } else {
            for (ClassNode cn : nodes) processClass(cn, report);
        }

        for (ClassNode cn : nodes) {
            byte[] b = writeClass(cn, true);
            if (b == null) b = writeClass(cn, false);
            if (b == null) { classFailed++; report.add("WRITE FAILED " + cn.name); continue; }
            output.put(cn.name + ".class", b);
            if (validate(b)) classValid++;
            else classInvalid++;
        }

        writeAll(out, output);
        printReport(out, report);
    }

    private void processClass(ClassNode cn, List<String> report) {
        ClassFacts facts = obtainFacts(cn);
        boolean refreshed = false;
        for (DeobPass p : effectivePasses()) {
            if (!refreshed && factPasses.contains(p)) {
                facts = boundFacts(cn, report);
                refreshed = true;
            }
            PassResult r = safeApply(p, cn, facts);
            accumulate(r);
            liveLine(p, cn, r);
        }
        if (!refreshed) facts = obtainFacts(cn);
        classifyClass(cn, facts, report);
        classCount++;
    }

    private void runStaged(List<ClassNode> nodes, List<String> report) {
        Map<String, ClassFacts> factsByName = new LinkedHashMap<>();
        for (ClassNode cn : nodes) factsByName.put(cn.name, obtainFacts(cn));
        boolean refreshed = false;
        int stageNo = 1;
        for (DeobPass p : effectivePasses()) {
            if (!refreshed && factPasses.contains(p)) {
                for (ClassNode cn : nodes) factsByName.put(cn.name, boundFacts(cn, report));
                refreshed = true;
            }
            PassResult stageAgg = new PassResult();
            for (ClassNode cn : nodes) {
                PassResult r = safeApply(p, cn, factsByName.get(cn.name));
                for (Map.Entry<String, Integer> e : r.counts.entrySet()) stageAgg.add(e.getKey(), e.getValue());
                accumulate(r);
                if (verbose) printDetails(p, r);
            }
            String phrase = p.describe(stageAgg);
            if (phrase.isEmpty()) phrase = "no change";
            log.println(tag(p.label()) + Ansi.grey("[stage " + String.format("%02d", stageNo) + "]") + " " + Ansi.numbers(phrase));
            dumpStageFromNodes(stageNo, p.id(), nodes);
            stageNo++;
        }
        for (ClassNode cn : nodes) classifyClass(cn, factsByName.get(cn.name), report);
        classCount = nodes.size();
    }

    private List<DeobPass> effectivePasses() {
        List<DeobPass> r = new ArrayList<>();
        for (DeobPass p : pipeline) {
            if (onlyIds == null || onlyIds.contains(p.id())) r.add(p);
            if (stopAfter != null && p.id().equals(stopAfter)) break;
        }
        return r;
    }

    private PassResult safeApply(DeobPass p, ClassNode cn, ClassFacts facts) {
        try {
            return p.apply(cn, facts);
        } catch (Throwable t) {
            PassResult r = new PassResult();
            r.detail("PASS ERROR " + p.id() + " on " + cn.name + ": " + t);
            return r;
        }
    }

    private ClassFacts obtainFacts(ClassNode cn) {
        if (!useFacts) {
            ClassFacts f = new ClassFacts();
            f.thisClass = cn.name;
            f.ok = true;
            return f;
        }
        ClassFacts f;
        try {
            f = new FactExtractor().extract(cn);
        } catch (Throwable t) {
            f = new ClassFacts();
            f.thisClass = cn.name;
            f.ok = false;
            f.error = "extract: " + t;
        }
        if (verbose)
            for (String w : f.warnings) log.println(Ansi.yellow("    [facts] " + cn.name + ": " + w));
        return f;
    }

    private void liveLine(DeobPass p, ClassNode cn, PassResult r) {
        if (r.changed() || verbose) {
            String phrase = p.describe(r);
            if (phrase.isEmpty()) phrase = "no change";
            log.println(tag(p.label()) + cn.name + ": " + Ansi.numbers(phrase));
        }
        if (verbose) printDetails(p, r);
    }

    private void printDetails(DeobPass p, PassResult r) {
        for (String d : r.details) {
            String line = "    [" + p.id() + "] " + d;
            log.println(d.startsWith("PASS ERROR") ? Ansi.red(line) : Ansi.grey(line));
        }
    }

    private void accumulate(PassResult r) {
        for (Map.Entry<String, Integer> e : r.counts.entrySet()) agg.merge(e.getKey(), e.getValue(), Integer::sum);
    }

    private void classifyClass(ClassNode cn, ClassFacts facts, List<String> report) {
        int residualDecryptors = 0, residualIndy = 0;
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            for (AbstractInsnNode n : mn.instructions.toArray())
                if (n instanceof InvokeDynamicInsnNode) {
                    Handle h = ((InvokeDynamicInsnNode) n).bsm;
                    if (h != null && h.getOwner().equals(cn.name)) residualIndy++;
                }
        }
        for (MethodNode mn : cn.methods)
            if (mn.desc.equals("(IILjava/lang/Object;)Ljava/lang/String;")
                || mn.desc.equals("([BLjava/lang/String;Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;"))
                residualDecryptors++;

        if (!facts.ok) {
            classFailed++;
            report.add("FAILED  " + cn.name + " (extract: " + facts.error + ")");
            log.println(Ansi.red(cn.name + ": FAILED (" + facts.error + ")"));
        } else if (residualDecryptors == 0 && residualIndy == 0) {
            classFullyResolved++;
            if (verbose) report.add("FULL    " + cn.name);
            log.println(Ansi.green(cn.name + ": FULLY DEOBFUSCATED"));
        } else {
            classPartial++;
            String msg = "residual decryptors=" + residualDecryptors + " linker-indy=" + residualIndy
                + (facts.warnings.isEmpty() ? "" : ", warnings=" + facts.warnings.size());
            report.add("PARTIAL " + cn.name + " (" + msg + ")");
            log.println(Ansi.yellow(cn.name + ": PARTIAL (" + msg + ")"));
        }
    }

    private static boolean isClass(byte[] b) {
        return b.length >= 4 && (b[0] & 0xff) == 0xCA && (b[1] & 0xff) == 0xFE
            && (b[2] & 0xff) == 0xBA && (b[3] & 0xff) == 0xBE;
    }

    private static String readInternalName(byte[] b) {
        return new ClassReader(b).getClassName();
    }

    private byte[] writeClass(ClassNode cn, boolean frames) {
        try {
            int flags = frames ? ClassWriter.COMPUTE_FRAMES : ClassWriter.COMPUTE_MAXS;
            ClassWriter cw = new ClassWriter(flags) {
                @Override protected String getCommonSuperClass(String t1, String t2) {
                    return env != null ? env.commonSuper(t1, t2) : "java/lang/Object";
                }
                @Override protected ClassLoader getClassLoader() {
                    return Deobfuscator.class.getClassLoader();
                }
            };
            cn.accept(cw);
            return cw.toByteArray();
        } catch (Throwable t) {
            return null;
        }
    }

    private boolean validate(byte[] b) {
        try {
            StringWriter sw = new StringWriter();
            CheckClassAdapter.verify(new ClassReader(b), false, new PrintWriter(sw));
            String s = sw.toString();
            if (s.isEmpty()) return true;
            if (s.contains("not present")) return true;
            return !s.contains("Exception") && !s.contains("Error");
        } catch (Throwable t) {
            try {
                new ClassReader(b).accept(new CheckClassAdapter(new ClassWriter(0), false), 0);
                return true;
            } catch (Throwable t2) {
                return false;
            }
        }
    }

    private void dumpStage(int no, String id, Map<String, byte[]> origBytes) {
        String dir = String.format("%s/stage-%02d-%s", stagesDir, no, id);
        try {
            for (Map.Entry<String, byte[]> e : origBytes.entrySet()) {
                Path p = Paths.get(dir, e.getKey() + ".class");
                Files.createDirectories(p.getParent());
                Files.write(p, e.getValue());
            }
        } catch (IOException e) {
            log.println(Ansi.red("stage dump failed: " + e));
        }
    }

    private void dumpStageFromNodes(int no, String id, List<ClassNode> nodes) {
        String dir = String.format("%s/stage-%02d-%s", stagesDir, no, id);
        for (ClassNode cn : nodes) {
            byte[] b = writeClass(cn, false);
            try {
                if (b != null) {
                    Path p = Paths.get(dir, cn.name + ".class");
                    Files.createDirectories(p.getParent());
                    Files.write(p, b);
                } else {
                    Path p = Paths.get(dir, cn.name + ".err");
                    Files.createDirectories(p.getParent());
                    Files.write(p, ("could not serialize at stage " + id).getBytes());
                }
            } catch (IOException e) {
                log.println(Ansi.red("stage dump failed: " + e));
            }
        }
    }

    private static Map<String, byte[]> readAll(String path) throws IOException {
        Map<String, byte[]> m = new LinkedHashMap<>();
        File f = new File(path);
        if (f.isFile() && (path.endsWith(".jar") || path.endsWith(".zip"))) {
            try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(f)))) {
                ZipEntry ze;
                while ((ze = zis.getNextEntry()) != null) {
                    byte[] data = zis.readAllBytes();
                    if (data.length == 0) continue;
                    m.put(ze.getName(), data);
                }
            }
        } else if (f.isDirectory()) {
            Path root = f.toPath();
            try (var stream = Files.walk(root)) {
                stream.filter(Files::isRegularFile).forEach(p -> {
                    try {
                        String rel = root.relativize(p).toString().replace('\\', '/');
                        m.put(rel, Files.readAllBytes(p));
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                });
            }
        } else if (f.isFile()) {
            m.put(f.getName(), Files.readAllBytes(f.toPath()));
        }
        return m;
    }

    private static void writeAll(String path, Map<String, byte[]> out) throws IOException {
        if (path.endsWith(".jar") || path.endsWith(".zip")) {
            File pf = new File(path).getParentFile();
            if (pf != null) pf.mkdirs();
            try (JarOutputStream jos = new JarOutputStream(new BufferedOutputStream(new FileOutputStream(path)))) {
                for (Map.Entry<String, byte[]> e : out.entrySet()) {
                    jos.putNextEntry(new ZipEntry(e.getKey()));
                    jos.write(e.getValue());
                    jos.closeEntry();
                }
            }
        } else {
            for (Map.Entry<String, byte[]> e : out.entrySet()) {
                File dst = new File(path, e.getKey());
                dst.getParentFile().mkdirs();
                Files.write(dst.toPath(), e.getValue());
            }
        }
    }

    private void banner() {
        log.println();
        log.println(Ansi.bold(Ansi.cyan(NAME)) + Ansi.grey("  v" + VERSION + "  automatic qProtect-Lite deobfuscator"));
        log.println();
    }

    private String tag(String label) {
        String t = "[" + label + "]";
        int pad = Math.max(0, TAG_WIDTH - t.length());
        return Ansi.cyan(t) + " ".repeat(pad) + " ";
    }

    private void printReport(String out, List<String> report) {
        System.out.println(Ansi.grey("------------------------------------------------------------------"));
        System.out.println(Ansi.grey("[qUnProtect] classes=" + classCount
            + " fullyResolved=" + classFullyResolved + " partial=" + classPartial
            + " failed=" + classFailed));
        System.out.println(Ansi.grey("[qUnProtect] valid(CheckClassAdapter)=" + classValid + " invalid=" + classInvalid));
        StringBuilder b = new StringBuilder();
        for (Map.Entry<String, Integer> e : agg.entrySet()) {
            if (b.length() > 0) b.append(' ');
            b.append(e.getKey()).append('=').append(e.getValue());
        }
        System.out.println(Ansi.grey("[qUnProtect] totals: " + b));
        if (!report.isEmpty()) {
            int shown = 0;
            for (String s : report) {
                if (s.startsWith("FULL") && !verbose) continue;
                System.out.println("   " + colorReportLine(s));
                if (++shown > 60 && !verbose) {
                    System.out.println("   ... (" + (report.size() - shown) + " more; -v for all)");
                    break;
                }
            }
        }
        System.out.println(Ansi.grey("[qUnProtect] -> " + out));
    }

    private static String colorReportLine(String s) {
        if (s.startsWith("FAILED") || s.startsWith("WRITE FAILED")) return Ansi.red(s);
        if (s.startsWith("PARTIAL")) return Ansi.yellow(s);
        if (s.startsWith("FULL")) return Ansi.green(s);
        return Ansi.grey(s);
    }

    private void printClass(String file) throws IOException {
        byte[] b = Files.readAllBytes(Paths.get(file));
        PrintWriter pw = new PrintWriter(System.out);
        new ClassReader(b).accept(new TraceClassVisitor(pw), 0);
        pw.flush();
    }

    private void listPasses() {
        env = new Env(Collections.emptyList());
        buildPipeline();
        System.out.println(NAME + " passes (fixed order):");
        int i = 1;
        for (DeobPass p : pipeline)
            System.out.printf("  %2d. %-12s  %s%n", i++, p.id(), p.desc());
    }

    private static void help() {
        System.out.println(String.join("\n",
            NAME + " " + VERSION + " - automatic qProtect-Lite deobfuscator",
            "",
            "usage: Deobfuscator <in.jar|dir> <out.jar|dir> [options]",
            "       Deobfuscator --passes",
            "       Deobfuscator --print <file.class>",
            "",
            "options:",
            "  --only <id[,id...]>   run only these passes (see --passes)",
            "  --stop-after <id>     run passes up to and including <id>",
            "  --stages <dir>        dump a snapshot of all classes after each pass",
            "                        (stage-00-input, stage-01-<id>, ...) to watch it live",
            "  -v, --verbose         per-class per-pass detail + full report",
            "  --no-facts            skip string/indy fact extraction (generic passes only)",
            "  --no-color            disable ANSI colour (auto-off when not a console)",
            "  --passes              list the passes in order and exit",
            "  --print <file.class>  ASM Textifier dump of a class (works on Java-25 v69)",
            "  -h, --help            this message"));
    }
}
