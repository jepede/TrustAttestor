package com.lingqing.trustattestor;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Queue;

/** Silent structural checks whose failures are represented as UNAVAILABLE rather than thrown. */
@SuppressLint({"BlockedPrivateApi", "PrivateApi", "SoonBlockedPrivateApi"})
final class StructuralKeystoreProbes {
    private static final String KEYSTORE2_SERVICE =
            "android.system.keystore2.IKeystoreService/default";
    private static final int SECURITY_LEVEL_TEE = 1;
    private static final int DEBUG_PID_TRANSACTION = ('_' << 24) | ('P' << 16) | ('I' << 8) | 'D';
    private static final long BINDER_ATTRIBUTES_AVAILABLE = 1L << 0;
    private static final long BINDER_ATTRIBUTES_REMOTE = 1L << 1;
    private static final long BINDER_ATTRIBUTES_USER_DATA = 1L << 2;
    private static final long BINDER_ATTRIBUTES_CLASS = 1L << 3;
    private static final int MAX_METADATA_ITEMS = 256;
    private static final int MAX_OBJECT_GRAPH_NODES = 256;
    private static final SecureRandom RANDOM = new SecureRandom();

    private StructuralKeystoreProbes() { }

    static final class Result {
        final String id;
        final SilentProbeEvidence.Status status;
        final String summary;
        final String detail;
        final Throwable failure;

        private Result(String id, SilentProbeEvidence.Status status, String summary,
                       String detail, Throwable failure) {
            this.id = id;
            this.status = status;
            this.summary = summary;
            this.detail = detail;
            this.failure = failure;
        }

        String debugDetail() {
            StringBuilder out = new StringBuilder(id).append(": ").append(status)
                    .append("; ").append(summary);
            if (detail != null && !detail.isEmpty()) out.append("\n").append(detail);
            if (failure != null) {
                out.append("\nrootFailure=").append(describe(failure));
                for (StackTraceElement frame : failure.getStackTrace()) {
                    out.append("\n  at ").append(frame);
                }
            }
            return out.toString();
        }
    }

    /** Checks captured, typed KeyMetadata objects without issuing another Keystore request. */
    static Result runMetadataSecurityLevels(Object... metadataObjects) {
        final String id = "M.metadata_security_level";
        try {
            List<StructuralProbeEvidence.SecurityLevelValue> values = new ArrayList<>();
            if (metadataObjects == null || metadataObjects.length == 0) {
                values.add(StructuralProbeEvidence.SecurityLevelValue.unavailable(
                        "KeyMetadata", "no captured object"));
            } else {
                for (int i = 0; i < metadataObjects.length; i++) {
                    collectMetadataLevels(metadataObjects[i], "metadata[" + i + "]", values);
                }
            }
            StructuralProbeEvidence.Decision decision =
                    StructuralProbeEvidence.securityLevels(values);
            return from(id, decision, null);
        } catch (Throwable failure) {
            return unavailable(id, "KeyMetadata securityLevel 检查未完成", failure);
        }
    }

    /**
     * Mirrors OMK Detector's three Binder-locality legs. All reflection, generation and cleanup
     * failures are contained in the returned result, so this probe cannot stop later checks.
     */
    static Result runBinderLocality() {
        return runBinderLocality(null);
    }

    /**
     * Runs the Binder-locality probe with the host application's class loader.
     *
     * The structural probes live in an embedded DEX loader, while the native
     * bridge lives in the host APK. Those loaders are not necessarily the
     * same, so resolving the bridge with Class.forName(String) alone can make
     * every leg look unavailable even though the Binder objects are valid.
     */
    static Result runBinderLocality(ClassLoader hostClassLoader) {
        return runBinderLocality(hostClassLoader, null);
    }

    /**
     * Runs locality against both a known business alias and a disposable control alias. The
     * known alias is important for OMK configurations that only synthesize carriers for keys in
     * their mirrored/scoop state; an arbitrary fresh alias can legitimately remain on System.
     */
    static Result runBinderLocality(ClassLoader hostClassLoader, String knownAlias) {
        final String id = "B.binder_locality";
        if (Build.VERSION.SDK_INT < 31) {
            return new Result(id, SilentProbeEvidence.Status.UNAVAILABLE,
                    "Android 12 之前没有可比的 Keystore2 Binder 路径",
                    "sdk=" + Build.VERSION.SDK_INT, null);
        }

        List<StructuralProbeEvidence.BinderLeg> legs = new ArrayList<>(3);
        Object service = null;
        Throwable serviceFailure = null;
        try {
            IBinder rawService = Keystore2ProbeAccess.binder();
            if (rawService == null) throw new IllegalStateException("Keystore2 service binder is null");
            legs.add(inspectBinder("IKeystoreService", rawService, hostClassLoader));
            service = keystoreService(rawService);
        } catch (Throwable failure) {
            serviceFailure = unwrap(failure);
        }

        if (service == null) {
            legs.add(unavailableLeg("getSecurityLevel", serviceFailure == null
                    ? "Keystore2 service unavailable" : describe(serviceFailure)));
        } else {
            legs.add(runSecurityLevelLeg(service, hostClassLoader));
        }

        KeyStore keyStore = null;
        String alias = null;
        boolean aliasReserved = false;
        Throwable rootFailure = serviceFailure;
        Throwable cleanupFailure = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            alias = unusedAlias(keyStore);
            aliasReserved = true;
            KeyPair pair = generateProbeKey(alias);
            if (pair == null || pair.getPrivate() == null) {
                throw new IllegalStateException("AndroidKeyStore returned an incomplete probe key");
            }

            if (service == null) {
                String why = serviceFailure == null ? "Keystore2 service unavailable" : describe(serviceFailure);
                legs.add(unavailableLeg("getKeyEntry.iSecurityLevel", why));
            } else {
                if (knownAlias != null && !knownAlias.isEmpty()) {
                    legs.add(runKeyEntryLeg(service, knownAlias, hostClassLoader,
                            "getKeyEntry.target.iSecurityLevel"));
                }
                legs.add(runKeyEntryLeg(service, alias, hostClassLoader));
            }
            legs.add(runOperationLeg(pair.getPrivate(), hostClassLoader));
        } catch (Throwable failure) {
            rootFailure = unwrap(failure);
            legs.add(unavailableLeg("getKeyEntry.iSecurityLevel",
                    "probe key unavailable: " + describe(rootFailure)));
            legs.add(unavailableLeg("IKeystoreOperation",
                    "probe key unavailable: " + describe(rootFailure)));
        } finally {
            // Generation can persist the alias before the provider throws or returns an incomplete
            // object. Once a fresh alias has been reserved, always attempt and verify cleanup.
            if (aliasReserved && keyStore != null && alias != null) {
                try {
                    keyStore.deleteEntry(alias);
                    if (keyStore.containsAlias(alias)) {
                        throw new IllegalStateException("probe alias still exists after deleteEntry");
                    }
                } catch (Throwable cleanupError) {
                    cleanupFailure = unwrap(cleanupError);
                }
            }
        }

        try {
            StructuralProbeEvidence.Decision decision = StructuralProbeEvidence.binderLocality(legs);
            if (cleanupFailure != null
                    && decision.status != SilentProbeEvidence.Status.DETECTED) {
                return new Result(id, SilentProbeEvidence.Status.UNAVAILABLE,
                        "Binder 本地性读数已取得，但临时密钥清理未完成",
                        decision.detail + "\ncleanupFailure=" + describe(cleanupFailure),
                        cleanupFailure);
            }
            return from(id, decision, cleanupFailure != null ? cleanupFailure : rootFailure);
        } catch (Throwable failure) {
            return unavailable(id, "Binder 本地性检查未完成", failure);
        }
    }

    private static void collectMetadataLevels(Object metadata, String path,
                                              List<StructuralProbeEvidence.SecurityLevelValue> out) {
        if (metadata == null) {
            out.add(StructuralProbeEvidence.SecurityLevelValue.unavailable(path, "null"));
            return;
        }
        readLevel(metadata, "keySecurityLevel", path + ".keySecurityLevel", out);
        collectContainer(metadata, "authorizations", path + ".authorizations", out, true);
        collectContainer(metadata, "keyCharacteristics", path + ".keyCharacteristics", out, false);
    }

    private static void collectContainer(Object owner, String fieldName, String path,
                                         List<StructuralProbeEvidence.SecurityLevelValue> out,
                                         boolean authorizationEntries) {
        FieldRead read = readField(owner, fieldName);
        if (!read.present) return; // Stable AIDL revisions do not all expose both containers.
        if (read.failure != null) {
            out.add(StructuralProbeEvidence.SecurityLevelValue.unavailable(path, describe(read.failure)));
            return;
        }
        if (read.value == null) return; // A nullable, empty container carries no level value.

        List<Object> entries = elements(read.value);
        if (entries == null) {
            out.add(StructuralProbeEvidence.SecurityLevelValue.unavailable(path,
                    "expected array or Collection, got " + read.value.getClass().getName()));
            return;
        }
        if (entries.size() > MAX_METADATA_ITEMS) {
            out.add(StructuralProbeEvidence.SecurityLevelValue.unavailable(path,
                    "entry limit exceeded: " + entries.size()));
            entries = entries.subList(0, MAX_METADATA_ITEMS);
        }
        for (int i = 0; i < entries.size(); i++) {
            Object entry = entries.get(i);
            String entryPath = path + "[" + i + "]";
            if (entry == null) {
                out.add(StructuralProbeEvidence.SecurityLevelValue.unavailable(entryPath, "null entry"));
                continue;
            }
            readLevel(entry, "securityLevel", entryPath + ".securityLevel", out);
            if (!authorizationEntries) {
                collectContainer(entry, "authorizations", entryPath + ".authorizations", out, true);
            }
        }
    }

    private static void readLevel(Object owner, String fieldName, String path,
                                  List<StructuralProbeEvidence.SecurityLevelValue> out) {
        FieldRead read = readField(owner, fieldName);
        if (!read.present) return;
        if (read.failure != null) {
            out.add(StructuralProbeEvidence.SecurityLevelValue.unavailable(path, describe(read.failure)));
            return;
        }
        Long numeric = securityLevelNumber(read.value);
        if (numeric == null) {
            out.add(StructuralProbeEvidence.SecurityLevelValue.unavailable(path,
                    read.value == null ? "null" : "unsupported type " + read.value.getClass().getName()));
        } else {
            out.add(StructuralProbeEvidence.SecurityLevelValue.observed(path, numeric));
        }
    }

    private static Long securityLevelNumber(Object value) {
        if (value instanceof Number) return ((Number) value).longValue();
        if (!(value instanceof Enum<?> e)) return null;
        return switch (e.name().toUpperCase(Locale.ROOT)) {
            case "SOFTWARE" -> 0L;
            case "TRUSTED_ENVIRONMENT", "TEE" -> 1L;
            case "STRONGBOX" -> 2L;
            case "KEYSTORE" -> 100L;
            default -> null;
        };
    }

    private static StructuralProbeEvidence.BinderLeg runSecurityLevelLeg(
            Object service, ClassLoader hostClassLoader) {
        final String name = "getSecurityLevel";
        try {
            Method method = findMethod(service.getClass(), "getSecurityLevel", 1);
            Object level = method.invoke(service, SECURITY_LEVEL_TEE);
            return inspectBinder(name, asBinder(level), hostClassLoader);
        } catch (Throwable failure) {
            return unavailableLeg(name, describe(unwrap(failure)));
        }
    }

    private static StructuralProbeEvidence.BinderLeg runKeyEntryLeg(
            Object service, String alias, ClassLoader hostClassLoader) {
        return runKeyEntryLeg(service, alias, hostClassLoader, "getKeyEntry.iSecurityLevel");
    }

    private static StructuralProbeEvidence.BinderLeg runKeyEntryLeg(
            Object service, String alias, ClassLoader hostClassLoader, String name) {
        try {
            Method method = findMethod(service.getClass(), "getKeyEntry", 1);
            Object descriptor = appDescriptor(method.getParameterTypes()[0], alias);
            Object response = method.invoke(service, descriptor);
            FieldRead read = readField(response, "iSecurityLevel");
            if (!read.present) return unavailableLeg(name, "reply has no iSecurityLevel field");
            if (read.failure != null) return unavailableLeg(name, describe(read.failure));
            if (read.value == null) return unavailableLeg(name, "iSecurityLevel is null");
            return inspectBinder(name, asBinder(read.value), hostClassLoader);
        } catch (Throwable failure) {
            return unavailableLeg(name, describe(unwrap(failure)));
        }
    }

    private static StructuralProbeEvidence.BinderLeg runOperationLeg(
            PrivateKey privateKey, ClassLoader hostClassLoader) {
        final String name = "IKeystoreOperation";
        Signature signature = null;
        boolean finished = false;
        try {
            signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            IBinder binder = findOperationBinder(signature);
            StructuralProbeEvidence.BinderLeg result = inspectBinder(name, binder, hostClassLoader);
            // The locality reading is already complete. Finishing only releases the operation;
            // a cleanup error must not erase a confirmed LOCAL/REMOTE observation.
            try {
                signature.update(new byte[]{0x54, 0x41});
                signature.sign();
                finished = true;
            } catch (Throwable ignored) {
            }
            return result;
        } catch (Throwable failure) {
            return unavailableLeg(name, describe(unwrap(failure)));
        } finally {
            if (signature != null && !finished) {
                try {
                    signature.update(new byte[]{0x54, 0x41});
                    signature.sign();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static StructuralProbeEvidence.BinderLeg inspectBinder(
            String name, IBinder binder, ClassLoader hostClassLoader) {
        if (binder == null) return unavailableLeg(name, "asBinder/object graph returned null");
        final long attributes;
        try {
            Method method = TrustAttestorNativeBridgeClass.method(hostClassLoader);
            Object value = method.invoke(null, binder);
            if (!(value instanceof Number)) {
                return unavailableLeg(name, "native Binder attribute bridge returned " + value);
            }
            attributes = ((Number) value).longValue();
        } catch (Throwable failure) {
            return unavailableLeg(name, "native Binder attribute bridge: " + describe(unwrap(failure)));
        }
        if ((attributes & BINDER_ATTRIBUTES_AVAILABLE) == 0) {
            return unavailableLeg(name, "native AIBinder attributes unavailable");
        }

        final boolean remote = (attributes & BINDER_ATTRIBUTES_REMOTE) != 0;
        final boolean userData = (attributes & BINDER_ATTRIBUTES_USER_DATA) != 0;
        final boolean classPresent = (attributes & BINDER_ATTRIBUTES_CLASS) != 0;
        String descriptor = "";
        String descriptorFailure = "";
        try {
            descriptor = binder.getInterfaceDescriptor();
        } catch (Throwable failure) {
            descriptorFailure = "descriptor=" + describe(unwrap(failure));
        }

        DebugPid pid = readDebugPid(binder);
        String detail = binder.getClass().getName()
                + "; remote=" + remote
                + "; userData=" + userData
                + "; class=" + classPresent
                + "; descriptor=" + (descriptor.isEmpty() ? "<unavailable>" : descriptor)
                + "; debugPid=" + (pid.known ? pid.value : "<unavailable>");
        if (!descriptorFailure.isEmpty()) detail += "; " + descriptorFailure;
        if (!pid.detail.isEmpty()) detail += "; " + pid.detail;
        return new StructuralProbeEvidence.BinderLeg(
                name,
                remote ? StructuralProbeEvidence.BinderLeg.Disposition.REMOTE
                        : StructuralProbeEvidence.BinderLeg.Disposition.LOCAL,
                detail,
                true,
                userData,
                classPresent,
                descriptor,
                pid.value,
                pid.known,
                pid.known && pid.value == android.os.Process.myPid());
    }

    private static DebugPid readDebugPid(IBinder binder) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!binder.transact(DEBUG_PID_TRANSACTION, data, reply, 0)) {
                return new DebugPid(false, -1, "debugPid transact=false");
            }
            if (reply.dataAvail() < Integer.BYTES) {
                return new DebugPid(false, -1, "debugPid reply too short: " + reply.dataAvail());
            }
            int value = reply.readInt();
            if (reply.dataAvail() != 0) {
                return new DebugPid(false, value,
                        "debugPid reply has trailing bytes=" + reply.dataAvail());
            }
            return new DebugPid(true, value, "");
        } catch (Throwable failure) {
            return new DebugPid(false, -1, "debugPid=" + describe(unwrap(failure)));
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static Object keystoreService(IBinder raw) throws Exception {
        Class<?> stub = Class.forName("android.system.keystore2.IKeystoreService$Stub");
        Method asInterface = stub.getDeclaredMethod("asInterface", IBinder.class);
        asInterface.setAccessible(true);
        Object service = asInterface.invoke(null, raw);
        if (service == null) throw new IllegalStateException("IKeystoreService.asInterface returned null");
        return service;
    }

    private static final class DebugPid {
        final boolean known;
        final int value;
        final String detail;

        DebugPid(boolean known, int value, String detail) {
            this.known = known;
            this.value = value;
            this.detail = detail == null ? "" : detail;
        }
    }

    private static final class TrustAttestorNativeBridgeClass {
        private static final String NAME =
                "com.lingqing.trustattestor.TrustAttestorNativeBridge";
        private static Method method;

        static synchronized Method method(ClassLoader hostClassLoader) throws Exception {
            if (method != null) return method;

            ClassLoader[] candidates = new ClassLoader[] {
                    hostClassLoader,
                    Thread.currentThread().getContextClassLoader(),
                    StructuralKeystoreProbes.class.getClassLoader(),
                    ClassLoader.getSystemClassLoader()
            };
            IdentityHashMap<ClassLoader, Boolean> seen = new IdentityHashMap<>();
            StringBuilder attempted = new StringBuilder();
            for (ClassLoader candidate : candidates) {
                if (candidate == null || seen.put(candidate, Boolean.TRUE) != null) continue;
                if (attempted.length() != 0) attempted.append(", ");
                attempted.append(candidate.getClass().getName());
                try {
                    Class<?> type = Class.forName(NAME, true, candidate);
                    Method resolved = type.getDeclaredMethod("binderAttributes", IBinder.class);
                    resolved.setAccessible(true);
                    method = resolved;
                    return resolved;
                } catch (ClassNotFoundException missing) {
                    // The embedded DEX loader is expected to miss the host-only
                    // Kotlin bridge on some devices; try the next loader.
                }
            }
            throw new ClassNotFoundException(NAME + "; attempted class loaders=" + attempted);
        }
    }

    private static Object appDescriptor(Class<?> descriptorClass, String alias) throws Exception {
        Object descriptor = descriptorClass.getDeclaredConstructor().newInstance();
        writeField(descriptor, "domain", 0);
        writeField(descriptor, "nspace", -1L);
        writeField(descriptor, "alias", alias);
        writeField(descriptor, "blob", null);
        return descriptor;
    }

    private static KeyPair generateProbeKey(String alias) throws Exception {
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                .build();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
        generator.initialize(spec);
        return generator.generateKeyPair();
    }

    private static String unusedAlias(KeyStore keyStore) throws Exception {
        for (int attempt = 0; attempt < 4; attempt++) {
            String alias = "__ta_binder_locality_" + android.os.Process.myPid() + "_"
                    + Long.toUnsignedString(SystemClock.elapsedRealtimeNanos()) + "_"
                    + Integer.toUnsignedString(RANDOM.nextInt());
            if (!keyStore.containsAlias(alias)) return alias;
        }
        throw new IllegalStateException("could not allocate an unused probe alias");
    }

    private static IBinder findOperationBinder(Object root) {
        if (root == null) return null;
        Map<Object, Boolean> seen = new IdentityHashMap<>();
        Queue<ObjectNode> queue = new ArrayDeque<>();
        queue.add(new ObjectNode(root, 0));
        int visited = 0;
        while (!queue.isEmpty() && visited++ < MAX_OBJECT_GRAPH_NODES) {
            ObjectNode node = queue.remove();
            Object value = node.value;
            if (value == null || node.depth > 4 || seen.put(value, Boolean.TRUE) != null) continue;
            Class<?> type = value.getClass();
            if (isOperationType(type)) {
                IBinder binder = asBinder(value);
                if (binder != null) return binder;
            }
            if (isGraphLeaf(type)) continue;
            for (Class<?> cursor = type; cursor != null && cursor != Object.class;
                 cursor = cursor.getSuperclass()) {
                for (Field field : cursor.getDeclaredFields()) {
                    if (Modifier.isStatic(field.getModifiers()) || field.getType().isPrimitive()
                            || field.getType().isArray() || field.getType() == String.class
                            || Collection.class.isAssignableFrom(field.getType())) continue;
                    try {
                        field.setAccessible(true);
                        Object child = field.get(value);
                        if (child != null) queue.add(new ObjectNode(child, node.depth + 1));
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
        return null;
    }

    private static boolean isOperationType(Class<?> type) {
        if (type.getName().contains("IKeystoreOperation")) return true;
        for (Class<?> iface : type.getInterfaces()) {
            if (iface.getName().contains("IKeystoreOperation")) return true;
        }
        return false;
    }

    private static boolean isGraphLeaf(Class<?> type) {
        String name = type.getName();
        return name.startsWith("javax.") || name.startsWith("android.os.")
                || name.startsWith("android.util.") || name.startsWith("java.lang.")
                || name.startsWith("java.util.") || name.startsWith("[L");
    }

    private static IBinder asBinder(Object object) {
        if (object == null) return null;
        if (object instanceof IBinder binder) return binder;
        try {
            Method method = findMethod(object.getClass(), "asBinder", 0);
            Object value = method.invoke(object);
            return value instanceof IBinder ? (IBinder) value : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Method findMethod(Class<?> type, String name, int parameterCount)
            throws NoSuchMethodException {
        for (Method method : type.getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == parameterCount) {
                try { method.setAccessible(true); } catch (Throwable ignored) { }
                return method;
            }
        }
        for (Class<?> cursor = type; cursor != null; cursor = cursor.getSuperclass()) {
            for (Method method : cursor.getDeclaredMethods()) {
                if (method.getName().equals(name) && method.getParameterCount() == parameterCount) {
                    try { method.setAccessible(true); } catch (Throwable ignored) { }
                    return method;
                }
            }
        }
        throw new NoSuchMethodException(type.getName() + "." + name + "/" + parameterCount);
    }

    private static FieldRead readField(Object target, String name) {
        if (target == null) return new FieldRead(false, null, null);
        Field field = findField(target.getClass(), name);
        if (field == null) return new FieldRead(false, null, null);
        try {
            field.setAccessible(true);
            return new FieldRead(true, field.get(target), null);
        } catch (Throwable failure) {
            return new FieldRead(true, null, unwrap(failure));
        }
    }

    private static Field findField(Class<?> type, String name) {
        for (Class<?> cursor = type; cursor != null; cursor = cursor.getSuperclass()) {
            try {
                return cursor.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
            }
        }
        return null;
    }

    private static void writeField(Object target, String name, Object value) throws Exception {
        Field field = findField(target.getClass(), name);
        if (field == null) throw new NoSuchFieldException(target.getClass().getName() + "." + name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static List<Object> elements(Object container) {
        if (container == null) return List.of();
        if (container.getClass().isArray()) {
            int length = Array.getLength(container);
            List<Object> result = new ArrayList<>(Math.min(length, MAX_METADATA_ITEMS));
            for (int i = 0; i < length; i++) result.add(Array.get(container, i));
            return result;
        }
        if (container instanceof Collection<?> collection) return new ArrayList<>(collection);
        return null;
    }

    private static StructuralProbeEvidence.BinderLeg unavailableLeg(String name, String why) {
        return new StructuralProbeEvidence.BinderLeg(name,
                StructuralProbeEvidence.BinderLeg.Disposition.UNAVAILABLE, why);
    }

    private static Result from(String id, StructuralProbeEvidence.Decision decision, Throwable failure) {
        return new Result(id, decision.status, decision.summary, decision.detail, failure);
    }

    private static Result unavailable(String id, String summary, Throwable failure) {
        Throwable cause = unwrap(failure);
        return new Result(id, SilentProbeEvidence.Status.UNAVAILABLE, summary,
                cause == null ? "unknown failure" : describe(cause), cause);
    }

    private static Throwable unwrap(Throwable failure) {
        Throwable cursor = failure;
        while ((cursor instanceof InvocationTargetException
                || cursor instanceof java.util.concurrent.ExecutionException)
                && cursor.getCause() != null && cursor.getCause() != cursor) {
            cursor = cursor.getCause();
        }
        return cursor;
    }

    private static String describe(Throwable failure) {
        if (failure == null) return "unknown";
        Throwable cause = unwrap(failure);
        String message = cause.getMessage();
        return cause.getClass().getName() + (message == null || message.isEmpty() ? "" : ": " + message);
    }

    // Plain immutable holders keep the probe portable across Android toolchains.
    private static final class FieldRead {
        final boolean present;
        final Object value;
        final Throwable failure;

        FieldRead(boolean present, Object value, Throwable failure) {
            this.present = present;
            this.value = value;
            this.failure = failure;
        }
    }

    private static final class ObjectNode {
        final Object value;
        final int depth;

        ObjectNode(Object value, int depth) {
            this.value = value;
            this.depth = depth;
        }
    }
}
