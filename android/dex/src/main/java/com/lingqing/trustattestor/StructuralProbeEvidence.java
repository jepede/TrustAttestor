package com.lingqing.trustattestor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Pure decision logic for structural Keystore probes. */
final class StructuralProbeEvidence {
    private StructuralProbeEvidence() { }

    static final class SecurityLevelValue {
        final String source;
        final Long value;
        final String unavailableReason;

        private SecurityLevelValue(String source, Long value, String unavailableReason) {
            this.source = source == null ? "unknown" : source;
            this.value = value;
            this.unavailableReason = unavailableReason;
        }

        static SecurityLevelValue observed(String source, long value) {
            return new SecurityLevelValue(source, value, null);
        }

        static SecurityLevelValue unavailable(String source, String reason) {
            return new SecurityLevelValue(source, null, reason == null ? "unreadable" : reason);
        }
    }

    static final class BinderLeg {
        enum Disposition { LOCAL, REMOTE, UNAVAILABLE }

        final String name;
        final Disposition disposition;
        final String detail;
        final boolean nativeAttributes;
        final boolean userDataPresent;
        final boolean classPresent;
        final String descriptor;
        final int debugPid;
        final boolean debugPidKnown;
        final boolean debugPidMatches;

        BinderLeg(String name, Disposition disposition, String detail) {
            this(name, disposition, detail, false, false, false, "", -1, false, false);
        }

        BinderLeg(String name, Disposition disposition, String detail,
                  boolean nativeAttributes, boolean userDataPresent, boolean classPresent,
                  String descriptor, int debugPid, boolean debugPidKnown,
                  boolean debugPidMatches) {
            this.name = name == null ? "unknown" : name;
            this.disposition = disposition == null ? Disposition.UNAVAILABLE : disposition;
            this.detail = detail == null ? "" : detail;
            this.nativeAttributes = nativeAttributes;
            this.userDataPresent = userDataPresent;
            this.classPresent = classPresent;
            this.descriptor = descriptor == null ? "" : descriptor;
            this.debugPid = debugPid;
            this.debugPidKnown = debugPidKnown;
            this.debugPidMatches = debugPidMatches;
        }

        boolean structuralMatch() {
            return disposition == Disposition.LOCAL
                    && nativeAttributes
                    && userDataPresent
                    && classPresent
                    && expectedDescriptor(name, descriptor);
        }

        boolean strongMatch() {
            return structuralMatch() && debugPidKnown && debugPidMatches;
        }

        private static boolean expectedDescriptor(String name, String descriptor) {
            if (descriptor == null || descriptor.isEmpty()) return false;
            if ("IKeystoreOperation".equals(name)) {
                return "android.system.keystore2.IKeystoreOperation".equals(descriptor);
            }
            if ("IKeystoreService".equals(name)) {
                return "android.system.keystore2.IKeystoreService".equals(descriptor);
            }
            return "android.system.keystore2.IKeystoreSecurityLevel".equals(descriptor);
        }
    }

    static final class Decision {
        final SilentProbeEvidence.Status status;
        final String summary;
        final String detail;

        Decision(SilentProbeEvidence.Status status, String summary, String detail) {
            this.status = status;
            this.summary = summary;
            this.detail = detail;
        }
    }

    static boolean isDefinedSecurityLevel(long value) {
        return value == 0L || value == 1L || value == 2L || value == 100L;
    }

    /**
     * A successfully decoded value outside the stable AIDL enum is a contradiction. Missing or
     * inaccessible fields remain unavailable and can never create a finding.
     */
    static Decision securityLevels(List<SecurityLevelValue> values) {
        List<SecurityLevelValue> safe = values == null ? Collections.emptyList() : values;
        int observed = 0;
        int unavailable = 0;
        List<String> invalid = new ArrayList<>();
        StringBuilder detail = new StringBuilder();
        for (SecurityLevelValue value : safe) {
            if (value == null) continue;
            if (value.value == null) {
                unavailable++;
                append(detail, value.source + "=unavailable(" + value.unavailableReason + ")");
                continue;
            }
            observed++;
            append(detail, value.source + "=" + value.value);
            if (!isDefinedSecurityLevel(value.value)) {
                invalid.add(value.source + "=" + value.value);
            }
        }
        if (!invalid.isEmpty()) {
            return new Decision(SilentProbeEvidence.Status.DETECTED,
                    "KeyMetadata 包含 AIDL 契约之外的 securityLevel",
                    "invalid=" + invalid + "; observed=" + observed + "; " + detail);
        }
        if (observed == 0) {
            return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                    "没有成功读取任何 KeyMetadata securityLevel",
                    "unavailable=" + unavailable + (detail.length() == 0 ? "" : "; " + detail));
        }
        return new Decision(SilentProbeEvidence.Status.VERIFIED,
                "已读取的 KeyMetadata securityLevel 均属于 AIDL 定义范围",
                "observed=" + observed + "; unavailable=" + unavailable + "; " + detail);
    }

    /**
     * Detects the current OMK carrier shape independently of the protocol probes. A local Binder
     * by itself is insufficient: the current injector must also expose NDK user data, an expected
     * AIDL descriptor and (when available) the current-process debug PID.
     */
    static Decision binderLocality(List<BinderLeg> legs) {
        List<BinderLeg> safe = legs == null ? Collections.emptyList() : legs;
        int local = 0;
        int remote = 0;
        int coreRemote = 0;
        int unavailable = 0;
        int structural = 0;
        int strong = 0;
        int suspiciousLocal = 0;
        StringBuilder detail = new StringBuilder();
        for (BinderLeg leg : safe) {
            if (leg == null) continue;
            switch (leg.disposition) {
                case LOCAL -> {
                    local++;
                    if (isCandidateBinderLeg(leg.name)) {
                        if (leg.structuralMatch()) structural++;
                        if (leg.strongMatch()) strong++;
                        else suspiciousLocal++;
                    }
                }
                case REMOTE -> {
                    remote++;
                    if (isCoreBinderLeg(leg.name)) coreRemote++;
                }
                case UNAVAILABLE -> unavailable++;
            }
            append(detail, leg.name + "=" + leg.disposition +
                    (leg.detail.isEmpty() ? "" : "(" + leg.detail + ")"));
        }
        if (structural > 0) {
            return new Decision(SilentProbeEvidence.Status.DETECTED,
                    "Keystore 返回了带 NDK 用户数据的 OMK synthetic Binder",
                    "structural=" + structural + "; strong=" + strong + "; local=" + local
                            + "; coreRemote=" + coreRemote + "; remote=" + remote
                            + "; unavailable=" + unavailable + "; " + detail);
        }
        if (suspiciousLocal > 0) {
            return new Decision(SilentProbeEvidence.Status.WARNING,
                    "Keystore 回复中出现未完成分类的本地 Binder",
                    "local=" + local + "; structural=0; strong=0; coreRemote=" + coreRemote
                            + "; remote=" + remote + "; unavailable=" + unavailable + "; " + detail);
        }
        if (coreRemote > 0) {
            return new Decision(SilentProbeEvidence.Status.VERIFIED,
                    "至少一个核心 Keystore 回复 Binder 为远端对象",
                    "coreRemote=" + coreRemote + "; remote=" + remote +
                            "; unavailable=" + unavailable + "; " + detail);
        }
        return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                "没有取得可判定本地性的核心 Keystore Binder 对象",
                "coreRemote=0; remote=" + remote + "; unavailable=" + unavailable +
                        (detail.length() == 0 ? "" : "; " + detail));
    }

    private static boolean isCoreBinderLeg(String name) {
        return (name != null && name.startsWith("getKeyEntry"))
                || "IKeystoreOperation".equals(name);
    }

    private static boolean isCandidateBinderLeg(String name) {
        return "getSecurityLevel".equals(name) || isCoreBinderLeg(name);
    }

    private static void append(StringBuilder builder, String value) {
        if (builder.length() > 0) builder.append("; ");
        builder.append(value);
    }
}
