package com.lingqing.trustattestor;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static com.lingqing.trustattestor.SilentProbeEvidence.Status.DETECTED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.UNAVAILABLE;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.VERIFIED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.WARNING;

/** Pure classification rules for the bounded OMK protocol fingerprints. */
final class OmkRiskyProbeEvidence {
    private OmkRiskyProbeEvidence() { }

    static final class Decision {
        final SilentProbeEvidence.Status status;
        final String summary;

        Decision(SilentProbeEvidence.Status status, String summary) {
            this.status = status;
            this.summary = summary;
        }
    }

    static final class Observation {
        enum BackendSource {
            OMK,
            AOSP_KEYSTORE2,
            UNKNOWN
        }

        final String name;
        final Integer serviceCode;
        final boolean success;
        final String outcome;
        final long elapsedMicros;
        /** Source family inferred from the exception's relative Rust source markers. */
        final BackendSource backendSource;

        Observation(String name, Integer serviceCode, boolean success,
                    String outcome, long elapsedMicros) {
            this(name, serviceCode, success, outcome, elapsedMicros,
                    classifyBackendSource(outcome));
        }

        Observation(String name, Integer serviceCode, boolean success,
                    String outcome, long elapsedMicros, BackendSource backendSource) {
            this.name = name;
            this.serviceCode = serviceCode;
            this.success = success;
            this.outcome = outcome;
            this.elapsedMicros = elapsedMicros;
            this.backendSource = backendSource == null ? BackendSource.UNKNOWN : backendSource;
        }

        String bucket() {
            if (success) return "success";
            return serviceCode == null ? "other:" + outcome : "code=" + serviceCode;
        }
    }

    /**
     * Classifies only relative source markers emitted by the backend error chain.  The detector
     * deliberately does not match an absolute device path: vendor builds can relocate their
     * checkout while preserving the implementation family.  A missing or mixed marker is
     * UNKNOWN and never becomes OMK evidence by itself.
     */
    static Observation.BackendSource classifyBackendSource(String text) {
        if (text == null || text.isEmpty()) return Observation.BackendSource.UNKNOWN;
        String normalized = text.replace('\\', '/').toLowerCase(Locale.US);
        boolean omk = normalized.contains("src/keymaster/security_level.rs");
        boolean aosp = normalized.contains("system/security/keystore2/src/security_level.rs");
        if (omk == aosp) return Observation.BackendSource.UNKNOWN;
        return omk ? Observation.BackendSource.OMK : Observation.BackendSource.AOSP_KEYSTORE2;
    }

    /** Passive evidence only; this class never sends Binder transactions. */
    static final class TokenReply {
        final String method;
        final String token;
        final int code;
        final boolean expectedToken;
        final boolean transactReturned;
        // Native fields are nullable: Java transact results do not expose these values.
        final Integer binderStatus;
        final Integer replyFlags;
        final Long offsetsSizeBytes;
        final ParsedStatus status;
        final String rawDigest;
        final String rawPrefix;

        TokenReply(String method, String token, int code, boolean expectedToken,
                   boolean transactReturned, Integer binderStatus, Integer replyFlags,
                   Long offsetsSizeBytes, byte[] rawReply) {
            this(method, token, code, expectedToken, transactReturned, binderStatus, replyFlags,
                    offsetsSizeBytes, parseStatus(rawReply), rawReply);
        }

        TokenReply(String method, String token, int code, boolean expectedToken,
                   boolean transactReturned, Integer binderStatus, Integer replyFlags,
                   Long offsetsSizeBytes, ParsedStatus parsedStatus, byte[] rawReply) {
            this.method = method;
            this.token = token;
            this.code = code;
            this.expectedToken = expectedToken;
            this.transactReturned = transactReturned;
            this.binderStatus = binderStatus;
            this.replyFlags = replyFlags;
            this.offsetsSizeBytes = offsetsSizeBytes;
            this.status = parsedStatus == null ? parseStatus(rawReply) : parsedStatus;
            this.rawDigest = rawReply == null ? null : sha256(rawReply);
            this.rawPrefix = prefix(rawReply, 32);
        }

        boolean complete() {
            // TF_STATUS_CODE identifies a native transport status, not an AIDL Status parcel.
            return transactReturned && (binderStatus == null || binderStatus == 0)
                    && (replyFlags == null || (replyFlags & 0x08) == 0) && status.valid;
        }

        boolean correctControl() {
            return expectedToken && complete() && Integer.valueOf(0).equals(status.exceptionCode);
        }

        boolean descriptorRejected() {
            // AIDL's enforceInterface writes EX_SECURITY after the Binder transport succeeds.
            // A false transact result remains a transport/unknown-transaction outcome and cannot
            // be turned into a clean descriptor rejection.
            return complete() && Integer.valueOf(-1).equals(status.exceptionCode);
        }

        boolean acceptedBusinessReply() {
            return !expectedToken && complete() && status.statusOnly
                    && Integer.valueOf(-8).equals(status.exceptionCode)
                    // A maintenance-shaped request can reach OMK's authoritative backend and
                    // return a real keystore ResponseCode.  KEY_NOT_FOUND (7) is the expected
                    // result for the random source descriptor used by the probe; older OMK
                    // builds returned a synthetic zero.  The endpoint/control checks below,
                    // rather than one hard-coded service code, provide the attribution guard.
                    && status.serviceSpecificCode != null;
        }

        String compact() {
            return method + "/" + token + "/transaction=" + code
                    + "/transactReturned=" + transactReturned + "/binderStatus=" + binderStatus
                    + "/replyFlags=" + replyFlags + "/dataSize=" + status.dataSize
                    + "/offsetsSizeBytes=" + offsetsSizeBytes
                    + "/exception=" + status.exceptionCode + "/service=" + status.serviceSpecificCode
                    + "/statusOnly=" + status.statusOnly + "/sha256=" + rawDigest
                    + "/rawPrefix=" + rawPrefix;
        }
    }

    /** Runtime shape of one same-code token leg. This is passive evidence for the classifier. */
    static final class TokenLeg {
        final boolean parcelBuilt;
        final boolean transactEntered;
        final boolean answered;
        final ParsedStatus status;
        final String phase;
        final String failureClass;
        final String failureMessage;
        final int dataBytes;
        final int replyBytes;

        TokenLeg(boolean parcelBuilt, boolean transactEntered, boolean answered,
                 ParsedStatus status, String phase, String failureClass,
                 String failureMessage, int dataBytes, int replyBytes) {
            this.parcelBuilt = parcelBuilt;
            this.transactEntered = transactEntered;
            this.answered = answered;
            this.status = status;
            this.phase = phase;
            this.failureClass = failureClass;
            this.failureMessage = failureMessage;
            this.dataBytes = dataBytes;
            this.replyBytes = replyBytes;
        }

        boolean complete() {
            return answered && status != null && status.valid;
        }

        boolean standardReject() {
            return complete() && Integer.valueOf(-1).equals(status.exceptionCode);
        }

        boolean omkReply() {
            return complete() && status.statusOnly
                    && Integer.valueOf(-8).equals(status.exceptionCode)
                    && status.serviceSpecificCode != null;
        }

        boolean postMarshalFailure() {
            return parcelBuilt && transactEntered && !answered;
        }

        boolean sameFailure(TokenLeg other) {
            if (other == null) return false;
            if (complete() || other.complete()) return false;
            return postMarshalFailure() && other.postMarshalFailure()
                    && equalsText(phase, other.phase)
                    && equalsText(failureClass, other.failureClass);
        }

        boolean isIllegalArgumentTransportFailure() {
            return postMarshalFailure()
                    && "transact".equals(phase)
                    && "java.lang.IllegalArgumentException".equals(failureClass);
        }

        String compact() {
            return "parcelBuilt=" + parcelBuilt + "/transactEntered=" + transactEntered
                    + "/answered=" + answered + "/phase=" + phase
                    + "/dataBytes=" + dataBytes + "/replyBytes=" + replyBytes
                    + "/exception=" + (status == null ? null : status.exceptionCode)
                    + "/service=" + (status == null ? null : status.serviceSpecificCode)
                    + "/failure=" + failureClass + ":" + failureMessage;
        }

        private static boolean equalsText(String left, String right) {
            return left == null ? right == null : left.equals(right);
        }
    }

    static final class ParsedStatus {
        final int dataSize;
        final Integer exceptionCode;
        final Integer serviceSpecificCode;
        final boolean valid;
        final boolean statusOnly;

        ParsedStatus(int dataSize, Integer exceptionCode, Integer serviceSpecificCode,
                     boolean valid, boolean statusOnly) {
            this.dataSize = dataSize;
            this.exceptionCode = exceptionCode;
            this.serviceSpecificCode = serviceSpecificCode;
            this.valid = valid;
            this.statusOnly = statusOnly;
        }
    }

    /** One legal or trailing-data leg of the raw IKeystoreService probe. */
    static final class TrailingReply {
        final String method;
        final boolean trailing;
        final boolean attempted;
        final boolean answered;
        final ParsedStatus status;
        final boolean payloadPresent;

        TrailingReply(String method, boolean trailing, boolean attempted, boolean answered,
                      ParsedStatus status, boolean payloadPresent) {
            this.method = method;
            this.trailing = trailing;
            this.attempted = attempted;
            this.answered = answered;
            this.status = status;
            this.payloadPresent = payloadPresent;
        }
    }

    /** Decodes a captured, little-endian AIDL Status envelope without Android APIs. */
    static ParsedStatus parseStatus(byte[] raw) {
        int size = raw == null ? -1 : raw.length;
        Integer exception = null;
        if (raw == null || raw.length < 4 || raw.length > 1_048_576 || (raw.length & 3) != 0) {
            return new ParsedStatus(size, null, null, false, false);
        }
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(raw).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        try {
            exception = buffer.getInt();
            // Parcel.readExceptionCode() consumes this optional fat StrictMode header before
            // returning the real exception code. Match that public AIDL behavior so a gathered
            // but harmless violation does not invalidate an otherwise successful control call.
            if (exception == -128) {
                if (buffer.remaining() < 4) throw new IllegalArgumentException("missing fat header");
                int headerSize = buffer.getInt();
                if (headerSize < 4 || headerSize - 4 > buffer.remaining()) {
                    throw new IllegalArgumentException("invalid fat header");
                }
                buffer.position(buffer.position() + headerSize - 4);
                if (!buffer.hasRemaining()) throw new IllegalArgumentException("missing exception code");
                exception = buffer.getInt();
            }
            // Unknown/extended headers stay incomplete. They cannot be treated as business replies.
            if (exception == 0) {
                return new ParsedStatus(size, exception, null, true, !buffer.hasRemaining());
            }
            // Android's BadParcelableException is encoded as EX_PARCELABLE (-9).  It is the
            // normal clean-AOSP outcome when enforceNoDataAvail() rejects a request tail.
            if (exception < -9 || exception > -1) {
                return new ParsedStatus(size, exception, null, false, false);
            }
            int messageChars = buffer.getInt();
            if (messageChars < -1) throw new IllegalArgumentException("invalid String16 length");
            if (messageChars >= 0) {
                long stringBytes = ((long) messageChars + 1L) * 2L;
                long paddedBytes = (stringBytes + 3L) & ~3L;
                if (paddedBytes > buffer.remaining()) throw new IllegalArgumentException("truncated String16");
                int start = buffer.position();
                if (buffer.getShort(start + messageChars * 2) != 0) {
                    throw new IllegalArgumentException("unterminated String16");
                }
                buffer.position(start + (int) paddedBytes);
            }
            int stackStart = buffer.position();
            int stackBytes = buffer.getInt();
            if (stackBytes < 0 || (stackBytes != 0 && (stackBytes < 4 || (stackBytes & 3) != 0
                    || stackBytes > raw.length - stackStart))) {
                throw new IllegalArgumentException("invalid stack header");
            }
            if (stackBytes != 0) buffer.position(stackStart + stackBytes);
            Integer serviceCode = exception == -8 ? buffer.getInt() : null;
            return new ParsedStatus(size, exception, serviceCode, true, !buffer.hasRemaining());
        } catch (java.nio.BufferUnderflowException | IndexOutOfBoundsException | IllegalArgumentException malformed) {
            return new ParsedStatus(size, exception, null, false, false);
        }
    }

    /**
     * Classifies raw AIDL and synthetic-Binder trailing-data legs. The clean leg is the required
     * baseline: a vendor may legally accept and ignore an extra field on both legs, which is not
     * evidence of OMK. A finding therefore requires a tail-only response change with a known
     * boundary meaning; reply length alone is never a finding.
     */
    static Decision trailingData(List<TrailingReply> rows) {
        if (rows == null || rows.isEmpty()) {
            return new Decision(UNAVAILABLE, "AIDL 尾部数据探针没有可用事务");
        }
        Map<String, TrailingReply> legal = new LinkedHashMap<>();
        Map<String, TrailingReply> tails = new LinkedHashMap<>();
        for (TrailingReply row : rows) {
            if (row == null || row.method == null || !row.attempted || !row.answered
                    || row.status == null || !row.status.valid) {
                return new Decision(UNAVAILABLE, "AIDL 尾部数据探针存在未完成或无法解析的回包");
            }
            (row.trailing ? tails : legal).put(row.method, row);
        }
        if (legal.isEmpty() || tails.isEmpty()) {
            return new Decision(UNAVAILABLE, "AIDL 尾部数据探针缺少合法请求或尾部请求对照");
        }
        int complete = 0;
        for (Map.Entry<String, TrailingReply> entry : legal.entrySet()) {
            TrailingReply clean = entry.getValue();
            TrailingReply tail = tails.get(entry.getKey());
            if (tail == null) continue;
            complete++;
            Integer tailException = tail.status.exceptionCode;
            boolean unchanged = sameTrailingReply(clean, tail);
            if (!unchanged && Integer.valueOf(0).equals(tailException)
                    && (!"getSecurityLevel".equals(tail.method) || tail.payloadPresent)) {
                return new Decision(DETECTED,
                        "IKeystoreService 的 " + tail.method
                                + " 接受了带非法尾部字段的 AIDL 请求"
                                + "; replyBytes=" + tail.status.dataSize);
            }
            if (!unchanged && !"syntheticOperation.updateAad".equals(tail.method)
                    && Integer.valueOf(-8).equals(tailException)
                    && tail.status.serviceSpecificCode != null) {
                return new Decision(DETECTED,
                        "IKeystoreService 的 " + tail.method
                                + " 对带非法尾部字段的请求返回了 OMK 风格 ServiceSpecific 回包"
                                + "; serviceCode=" + tail.status.serviceSpecificCode);
            }
            if ("syntheticOperation.updateAad".equals(tail.method)
                    // The runtime probe now creates two independent, valid GCM operations. A
                    // clean updateAad must succeed. A generated AOSP Stub must then reject the
                    // extra field with EX_PARCELABLE (-9). If the tail instead reaches the
                    // operation implementation and returns either a normal reply or a complete
                    // ServiceSpecific result, the synthetic carrier accepted data beyond the
                    // AIDL boundary. The old EC/non-AAD probe produced the same -40 -> -28
                    // lifecycle on clean devices and is intentionally excluded because its clean
                    // leg was already an operation error.
                    && Integer.valueOf(0).equals(clean.status.exceptionCode)
                    && tail.status.statusOnly
                    && (Integer.valueOf(0).equals(tailException)
                    || Integer.valueOf(-8).equals(tailException))) {
                String suffix = Integer.valueOf(-8).equals(tailException)
                        ? "; serviceCode=" + tail.status.serviceSpecificCode
                        : "; tailReply=success";
                return new Decision(DETECTED,
                        "合法 GCM Operation 的尾部请求未在 Stub 边界拒绝，已到达 synthetic Operation 实现"
                                + suffix + "; cleanReplyBytes=" + clean.status.dataSize
                                + "; tailReplyBytes=" + tail.status.dataSize);
            }
            // Keep the legal leg referenced so a future implementation cannot accidentally
            // classify an unmatched tail as a complete control.
            if (clean.status.exceptionCode == null) {
                return new Decision(UNAVAILABLE, "AIDL 合法请求对照缺少异常码");
            }
        }
        if (complete == 0) {
            return new Decision(UNAVAILABLE, "AIDL 尾部数据探针没有成对的合法请求对照");
        }
        return new Decision(VERIFIED,
                "尾部数据合法/追加请求完成，但未形成尾部专属异常差分；完成事务=" + complete);
    }

    private static boolean sameTrailingReply(TrailingReply clean, TrailingReply tail) {
        if (clean == null || tail == null || clean.status == null || tail.status == null) {
            return false;
        }
        return clean.status.dataSize == tail.status.dataSize
                && java.util.Objects.equals(clean.status.exceptionCode, tail.status.exceptionCode)
                && java.util.Objects.equals(clean.status.serviceSpecificCode,
                        tail.status.serviceSpecificCode)
                && clean.status.statusOnly == tail.status.statusOnly
                && clean.payloadPresent == tail.payloadPresent;
    }

    private static String sha256(byte[] raw) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(raw);
            StringBuilder text = new StringBuilder(64);
            for (byte value : digest) {
                int unsigned = value & 0xff;
                if (unsigned < 16) text.append('0');
                text.append(Integer.toHexString(unsigned));
            }
            return text.toString();
        } catch (java.security.NoSuchAlgorithmException missing) {
            return null;
        }
    }

    private static String prefix(byte[] raw, int maxBytes) {
        if (raw == null || raw.length == 0) return "";
        int length = Math.min(maxBytes, raw.length);
        StringBuilder text = new StringBuilder(length * 2);
        for (int index = 0; index < length; index++) {
            int unsigned = raw[index] & 0xff;
            if (unsigned < 16) text.append('0');
            text.append(Integer.toHexString(unsigned));
        }
        return text.toString();
    }

    static final class TokenDispatchInput {
        final boolean targetDescriptorVerified;
        final boolean versionVerified;
        final int interfaceVersion;
        final List<TokenReply> replies;
        final TokenReply correctBefore;
        final TokenReply correctAfter;
        final boolean recoveryChanged;
        final boolean cleanupVerified;

        TokenDispatchInput(boolean targetDescriptorVerified, boolean versionVerified,
                           int interfaceVersion, List<TokenReply> replies,
                           TokenReply correctBefore, TokenReply correctAfter,
                           boolean recoveryChanged, boolean cleanupVerified) {
            this.targetDescriptorVerified = targetDescriptorVerified;
            this.versionVerified = versionVerified;
            this.interfaceVersion = interfaceVersion;
            this.replies = replies;
            this.correctBefore = correctBefore;
            this.correctAfter = correctAfter;
            this.recoveryChanged = recoveryChanged;
            this.cleanupVerified = cleanupVerified;
        }
    }

    static Decision tokenDispatch(TokenDispatchInput input) {
        if (input == null || !input.targetDescriptorVerified || !input.versionVerified
                || input.interfaceVersion < 0 || !input.cleanupVerified) {
            return new Decision(UNAVAILABLE, "Passive token evidence lacks verified endpoint/version/cleanup");
        }
        if (input.replies == null || input.replies.isEmpty()
                || input.correctBefore == null || input.correctAfter == null
                || !input.correctBefore.correctControl() || !input.correctAfter.correctControl()
                || input.correctBefore.code != input.correctAfter.code
                || !java.util.Objects.equals(input.correctBefore.method, input.correctAfter.method)) {
            return new Decision(UNAVAILABLE, "Correct-token controls are missing or failed");
        }
        Map<Integer, TokenReply> controls = new LinkedHashMap<>();
        for (TokenReply row : input.replies) {
            if (row != null && row.correctControl()) controls.put(row.code, row);
        }
        Map<String, Integer> repetitions = new LinkedHashMap<>();
        Map<String, TokenReply> samples = new LinkedHashMap<>();
        boolean randomRejected = false;
        int observed = 0;
        int completeObserved = 0;
        int rejected = 0;
        int incompleteObserved = 0;
        boolean incompleteCore = false;
        for (TokenReply row : input.replies) {
            if (row == null) return new Decision(UNAVAILABLE, "Passive token evidence has a missing sample");
            if (row.expectedToken) continue;
            if ("unknown".equals(row.method)) continue;
            observed++;
            TokenReply control = controls.get(row.code);
            if (!row.complete()) {
                // OEM Binder implementations may reject an unsupported read-only transaction at
                // the transport boundary. That is not evidence of the token-routing bug, but it
                // also must not turn an otherwise valid clean scan into UNAVAILABLE. Keep core
                // uncertainty visible as WARNING while allowing optional methods to be omitted.
                incompleteObserved++;
                if (isCoreTokenMethod(row.method)) incompleteCore = true;
                continue;
            }
            completeObserved++;
            if (row.descriptorRejected()) {
                rejected++;
                if ("random".equals(row.token) || row.token.startsWith("trustattestor.random.")) {
                    randomRejected = true;
                }
                continue;
            }
            if (row.acceptedBusinessReply() && control != null
                    && java.util.Objects.equals(control.method, row.method)
                    && row.rawDigest != null) {
                String group = row.token + "/" + row.code + "/" + row.rawDigest;
                repetitions.merge(group, 1, Integer::sum);
                samples.put(group, row);
            }
        }
        if (observed == 0) return new Decision(UNAVAILABLE, "No passive mismatched-token evidence");
        Map<String, Set<Integer>> repeatedCodes = new LinkedHashMap<>();
        Map<String, Set<String>> repeatedMethods = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> group : repetitions.entrySet()) {
            if (group.getValue() < 2) continue;
            TokenReply row = samples.get(group.getKey());
            if (!isMaintenanceToken(row.token)) continue;
            repeatedCodes.computeIfAbsent(row.token, unused -> new LinkedHashSet<>()).add(row.code);
            repeatedMethods.computeIfAbsent(row.token, unused -> new LinkedHashSet<>()).add(row.method);
        }
        for (Map.Entry<String, Set<Integer>> token : repeatedCodes.entrySet()) {
            Set<String> methods = repeatedMethods.get(token.getKey());
            if (token.getValue().size() >= 2 && randomRejected && !input.recoveryChanged
                    && allSafeReadOnlyMethods(methods)) {
                return new Decision(DETECTED, "Captured interface-boundary anomaly: repeated service-specific replies"
                        + "; token=" + token.getKey() + "; transactions=" + token.getValue()
                        + "; service-specific response preserved; random-token rejection control present; sample="
                        + samples.values().iterator().next().compact());
            }
        }
        if (completeObserved == 0) {
            return new Decision(SilentProbeEvidence.Status.WARNING,
                    "No complete mismatched-token reply was available; incomplete=" + incompleteObserved);
        }
        if (incompleteCore || !samples.isEmpty() || rejected != completeObserved || input.recoveryChanged) {
            return new Decision(SilentProbeEvidence.Status.WARNING,
                    "Passive token evidence is inconclusive; acceptedGroups=" + samples.size()
                            + "; incomplete=" + incompleteObserved
                            + "; recoveryChanged=" + input.recoveryChanged);
        }
        return new Decision(VERIFIED, "Captured mismatched-token replies are compatible with descriptor rejection"
                + "; observed=" + observed + "; interfaceVersion=" + input.interfaceVersion);
    }

    /**
     * Classifier for the production Binder probe. The reflected migration transaction is first
     * called with the real service token and a matching read-only service payload, then with the
     * maintenance token and the exact migration payload. This makes a transport-level false
     * result meaningful only when the service-token control answered on the same Binder and both
     * getKeyEntry controls survived.
     */
    static Decision tokenDispatch(boolean healthBefore, boolean healthAfter,
                                  int reflectedCode, String serviceMethod,
                                  TokenLeg serviceControl, TokenLeg randomControl,
                                  TokenLeg maintenance, TokenLeg maintenanceRepeat) {
        if (!healthBefore) {
            return new Decision(UNAVAILABLE, "正确接口对照在探测前不可用");
        }
        if (!healthAfter) {
            return new Decision(UNAVAILABLE, "探测后正确接口对照失败，结果作废");
        }

        boolean serviceGood = serviceControl != null && serviceControl.complete();
        if (maintenance == null || !maintenance.parcelBuilt) {
            return new Decision(WARNING,
                    "maintenance 请求未完成 Parcel 编码；未形成异常证据"
                            + "; code=" + reflectedCode + "; phase="
                            + (maintenance == null ? "missing" : maintenance.phase));
        }
        if (maintenance.omkReply()) {
            return new Decision(DETECTED,
                    "伪装 maintenance interface token 的反射事务 " + reflectedCode
                            + " 返回了 OMK 风格的 ServiceSpecific 回包"
                            + "; serviceCode=" + maintenance.status.serviceSpecificCode
                            + "; 同码服务方法=" + serviceMethod);
        }
        if (randomControl == null || !randomControl.parcelBuilt) {
            return new Decision(WARNING,
                    "随机 token 同码对照未完成；maintenance 结果无法归因"
                            + "; code=" + reflectedCode);
        }

        boolean repeated = maintenanceRepeat != null
                && maintenance.sameFailure(maintenanceRepeat);
        if (serviceGood && randomControl.standardReject()
                && maintenance.isIllegalArgumentTransportFailure() && repeated) {
            return new Decision(DETECTED,
                    "maintenance token 在同码、同 payload 下产生可重复的独有 Binder 参数异常"
                            + "; code=" + reflectedCode + "; serviceMethod=" + serviceMethod
                            + "; random=" + randomControl.compact()
                            + "; maintenance=" + maintenance.compact());
        }

        if (maintenance.complete() && randomControl.standardReject()) {
            return new Decision(VERIFIED,
                    "maintenance token 与随机 token 均被当前 Binder 按接口边界拒绝"
                            + "; code=" + reflectedCode + "; serviceMethod=" + serviceMethod);
        }
        if (maintenance.sameFailure(maintenanceRepeat)
                && maintenance.postMarshalFailure()
                && randomControl.standardReject()) {
            return new Decision(WARNING,
                    "maintenance token 与随机 token 的同码行为不同，但异常类型不足以独立归因"
                            + "; code=" + reflectedCode + "; maintenance="
                            + maintenance.compact());
        }
        return new Decision(WARNING,
                "同码 token 对照未形成完整 OMK 回包或稳定分类差异"
                        + "; code=" + reflectedCode + "; random="
                        + randomControl.compact() + "; maintenance=" + maintenance.compact());
    }

    static Decision tokenDispatch(boolean healthBefore, boolean serviceControlAttempted,
                                  boolean serviceControlAnswered, boolean migrateAttempted,
                                  boolean migrateAnswered, boolean healthAfter,
                                  int reflectedCode, String serviceMethod,
                                  ParsedStatus migrateStatus) {
        if (!healthBefore) {
            return new Decision(UNAVAILABLE, "正确接口对照在探测前不可用");
        }
        if (!healthAfter) {
            return new Decision(UNAVAILABLE, "探测后正确接口对照失败，结果作废");
        }
        if (!migrateAttempted) {
            // Payload construction or a vendor Binder ABI can prevent the destructive-looking
            // migration-shaped request from being sent. That is a safe probe limitation, not a
            // failed health check and not anomaly evidence. Keep the result complete and neutral.
            return new Decision(VERIFIED,
                    "反射得到的同码 maintenance 请求未能在本机 ABI 上安全发出；未形成异常证据");
        }
        if (!migrateAnswered) {
            // A clean framework can reject the migration-shaped payload locally or at the
            // colliding service method because the two transaction schemas differ. A transport
            // failure therefore carries no OMK evidence; only a parseable OMK-shaped reply does.
            return new Decision(VERIFIED,
                    "伪装 maintenance token 的反射事务 " + reflectedCode
                            + " 未回包或被本机 ABI 拒绝；未形成异常证据");
        }
        if (migrateStatus == null || !migrateStatus.valid) {
            return new Decision(VERIFIED,
                    "伪装 maintenance interface token 的反射回包格式不兼容；未形成异常证据");
        }
        // OMK's rewrite path can answer a maintenance-shaped request even though the real
        // IKeystoreService Stub would reject the interface token.  The authoritative maintenance
        // path preserves the complete EX_SERVICE_SPECIFIC (-8) envelope and its business code.
        // KEY_NOT_FOUND=7 is the documented result for the probe's random source descriptor;
        // older builds returned service code 0.  Do not classify by reply length or by one
        // historical code: the same-binder controls and before/after health checks are the
        // attribution guard.
        if (migrateStatus != null && migrateStatus.valid && migrateStatus.statusOnly
                && Integer.valueOf(-8).equals(migrateStatus.exceptionCode)
                 && migrateStatus.serviceSpecificCode != null) {
            if (!serviceControlAttempted || !serviceControlAnswered) {
                return new Decision(DETECTED,
                        "伪装 maintenance interface token 的反射事务 " + reflectedCode
                                + " 返回了 OMK 风格的 ServiceSpecific 回包"
                                + "; serviceCode=" + migrateStatus.serviceSpecificCode
                                + "; 同码服务对照不可用但回包特征明确");
            }
            return new Decision(DETECTED,
                    "伪装 maintenance interface token 的反射事务 " + reflectedCode
                            + " 返回了 OMK 风格的 ServiceSpecific 回包"
                            + "; serviceCode=" + migrateStatus.serviceSpecificCode
                            + "; 同码服务方法=" + serviceMethod);
        }
        return new Decision(VERIFIED,
                "伪装 maintenance interface token 的反射事务 " + reflectedCode
                        + " 收到非 OMK 归因的 Binder/AIDL 回包（同码服务方法：" + serviceMethod + "）");
    }

    private static boolean isCoreTokenMethod(String method) {
        return "getKeyEntry".equals(method) || "getSecurityLevel".equals(method);
    }

    private static boolean isMaintenanceToken(String token) {
        return token != null && token.endsWith("IKeystoreMaintenance");
    }

    private static boolean allSafeReadOnlyMethods(Set<String> methods) {
        if (methods == null || methods.size() < 2) return false;
        for (String method : methods) {
            if (!("listEntries".equals(method) || "listEntriesBatched".equals(method)
                    || "getNumberOfEntries".equals(method)
                    || "getSupplementaryAttestationInfo".equals(method))) {
                return false;
            }
        }
        return true;
    }
    static Decision parameterFingerprint(boolean healthBefore, boolean healthAfter,
                                         List<Observation> rows, Boolean taPatchTagsPresent) {
        if (!healthBefore) return new Decision(UNAVAILABLE, "参数探针前证明金丝雀失败");
        if (!healthAfter) return new Decision(UNAVAILABLE, "参数探针后证明金丝雀失败，读数作废");
        if (rows == null) return new Decision(UNAVAILABLE, "没有参数指纹读数");

        // The parameter profile is a compatibility observation.  A standard KeyMint parser can
        // legitimately return tag-specific errors, so the profile itself must never promote a
        // device to DETECTED.  The independent backend-provenance report, built from these same
        // rows, owns the high-confidence OMK finding.
        if (rows.size() != 6) {
            return new Decision(VERIFIED,
                    "本机私有 KeyMint ABI 仅返回 " + rows.size()
                            + " 条向量，参数画像不形成软件转发结论；TA补丁标签="
                            + taPatchTagsPresent);
        }

        Map<String, Integer> expectedCodes = new LinkedHashMap<>();
        expectedCodes.put("ALGORITHM", -4);
        expectedCodes.put("BLOCK_MODE", -7);
        expectedCodes.put("DIGEST", -10);
        Map<String, Observation> byName = new LinkedHashMap<>();
        Map<String, Integer> distribution = new LinkedHashMap<>();
        Set<Observation.BackendSource> sources = new LinkedHashSet<>();
        boolean duplicateName = false;
        boolean complete = true;
        boolean accepted = false;
        boolean exactMapping = true;
        for (Observation row : rows) {
            if (row == null || row.name == null || byName.put(row.name, row) != null) {
                duplicateName = true;
                continue;
            }
            sources.add(row.backendSource);
            if (row.success) {
                accepted = true;
                exactMapping = false;
                distribution.merge("success", 1, Integer::sum);
                continue;
            }
            if (row.serviceCode == null) {
                complete = false;
                exactMapping = false;
                continue;
            }
            distribution.merge(row.bucket(), 1, Integer::sum);
            int separator = row.name.indexOf('+');
            String family = separator <= 0 ? null : row.name.substring(0, separator);
            Integer expected = expectedCodes.get(family);
            if (expected == null || !expected.equals(row.serviceCode)) exactMapping = false;
        }
        for (String family : expectedCodes.keySet()) {
            if (!byName.containsKey(family + "+Integer")
                    || !byName.containsKey(family + "+Blob")) {
                complete = false;
                exactMapping = false;
            }
        }
        if (duplicateName) {
            complete = false;
            exactMapping = false;
        }

        String evidence = "rows=" + rows.size() + "；分布=" + distribution
                + "；exactMapping=" + exactMapping + "；sources=" + sources
                + "；TA补丁标签=" + taPatchTagsPresent;
        if (!complete) {
            return new Decision(WARNING,
                    "参数画像矩阵已返回但存在缺失、重复或不可分类向量；未形成软件转发结论；"
                            + evidence);
        }
        if (accepted) {
            return new Decision(WARNING,
                    "参数画像包含被接受的类型错配请求；该行为可能是厂商兼容路径，未形成软件转发结论；"
                            + evidence);
        }

        if (sources.size() == 1
                && sources.contains(Observation.BackendSource.AOSP_KEYSTORE2)) {
            return new Decision(VERIFIED,
                    "参数错误映射来自厂商/AOSP Keystore2；后端来源未显示软件转发；" + evidence);
        }
        if (sources.size() == 1
                && sources.contains(Observation.BackendSource.OMK)) {
            return new Decision(VERIFIED,
                    "参数错误映射来自 OMK 后端；高风险结论由独立后端来源报告承担；" + evidence);
        }
        if (!exactMapping) {
            return new Decision(WARNING,
                    "参数错误映射与本机预期不完全一致，且后端来源不足以归因；" + evidence);
        }
        return new Decision(WARNING,
                "参数错误映射完整，但后端来源混合或未知；未形成软件转发结论；" + evidence);
    }

    /**
     * Independently classifies the backend family that produced the parameter error chain.
     * This consumes only this probe's canaries and its own six malformed-operation rows.  It
     * intentionally does not consult token routing, Binder locality, certificate, or any other
     * probe result.  Every tag family must provide both malformed union kinds and the same source
     * family; a partial or mixed chain is not strong enough to call either implementation.
     */
    static Decision backendProvenance(boolean healthBefore, boolean healthAfter,
                                      List<Observation> rows) {
        if (!healthBefore) return new Decision(UNAVAILABLE, "后端来源指纹探针前证明金丝雀失败");
        if (!healthAfter) return new Decision(UNAVAILABLE, "后端来源指纹探针后证明金丝雀失败，读数作废");
        if (rows == null || rows.isEmpty()) {
            return new Decision(UNAVAILABLE, "没有后端来源指纹向量");
        }

        Map<String, Set<Observation.BackendSource>> families = new LinkedHashMap<>();
        Map<String, Integer> familyCounts = new LinkedHashMap<>();
        Map<Observation.BackendSource, Integer> sources = new LinkedHashMap<>();
        int usable = 0;
        int successful = 0;
        int uncoded = 0;
        for (Observation row : rows) {
            if (row == null) continue;
            if (row.success) {
                successful++;
                continue;
            }
            if (row.serviceCode == null) {
                uncoded++;
            }
            String family = parameterFamily(row.name);
            if (family == null) continue;
            families.computeIfAbsent(family, ignored -> new LinkedHashSet<>())
                    .add(row.backendSource);
            familyCounts.merge(family, 1, Integer::sum);
            if (row.backendSource != Observation.BackendSource.UNKNOWN) {
                usable++;
                sources.merge(row.backendSource, 1, Integer::sum);
            }
        }

        // The current bounded probe is deliberately six rows: two malformed value unions for
        // each of ALGORITHM, BLOCK_MODE, and DIGEST.  Do not turn a shortened ABI run into a
        // source claim just because one row happened to contain a recognizable string.
        if (rows.size() != 6) {
            return new Decision(UNAVAILABLE,
                    "后端来源指纹向量不足或包含成功/未知异常；" + backendEvidence(rows, families, sources));
        }
        if (successful != 0) {
            return new Decision(WARNING,
                    "参数探针已完成，但包含成功响应，未形成可独立归因的错误栈来源；"
                            + backendEvidence(rows, families, sources));
        }
        if (families.size() < 3 || usable != 6 || uncoded != 0) {
            return new Decision(WARNING,
                    "参数探针已完成，但部分错误栈来源未知，不能严格区分后端；"
                            + backendEvidence(rows, families, sources));
        }
        for (String family : new String[]{"ALGORITHM", "BLOCK_MODE", "DIGEST"}) {
            Set<Observation.BackendSource> observed = families.get(family);
            if (!Integer.valueOf(2).equals(familyCounts.get(family))
                    || observed == null || observed.size() != 1
                    || observed.contains(Observation.BackendSource.UNKNOWN)) {
                return new Decision(WARNING,
                        "参数异常链在 " + family + " 家族内不稳定，不能严格区分后端；"
                                + backendEvidence(rows, families, sources));
            }
        }

        if (sources.size() == 1 && sources.containsKey(Observation.BackendSource.OMK)) {
            return new Decision(DETECTED,
                    "参数错误链稳定来自 OMK keymaster backend；"
                            + backendEvidence(rows, families, sources));
        }
        if (sources.size() == 1 && sources.containsKey(Observation.BackendSource.AOSP_KEYSTORE2)) {
            return new Decision(VERIFIED,
                    "参数错误链稳定来自厂商/AOSP Keystore2 backend；"
                            + backendEvidence(rows, families, sources));
        }
        return new Decision(WARNING,
                "参数错误链包含多个后端来源，不能安全归因；"
                        + backendEvidence(rows, families, sources));
    }

    private static String parameterFamily(String name) {
        if (name == null) return null;
        int separator = name.indexOf('+');
        if (separator <= 0) return null;
        String family = name.substring(0, separator).toUpperCase(Locale.US);
        if ("ALGORITHM".equals(family) || "BLOCK_MODE".equals(family)
                || "DIGEST".equals(family)) return family;
        return null;
    }

    private static String backendEvidence(List<Observation> rows,
                                          Map<String, Set<Observation.BackendSource>> families,
                                          Map<Observation.BackendSource, Integer> sources) {
        return "rows=" + (rows == null ? 0 : rows.size())
                + "；families=" + families + "；sources=" + sources;
    }

    static Decision teeSimFingerprint(boolean healthBefore, boolean healthAfter,
                                      List<Observation> rows, boolean evidenceInvalidated) {
        if (!healthBefore) return new Decision(UNAVAILABLE, "TeeSim 探针前证明金丝雀失败");
        if (!healthAfter) return new Decision(UNAVAILABLE, "TeeSim 探针后证明金丝雀失败，读数作废");
        if (rows == null || rows.isEmpty()) return new Decision(UNAVAILABLE, "没有 TeeSim 指纹读数");
        if (evidenceInvalidated) {
            return new Decision(UNAVAILABLE, "临时密钥清理失败，TeeSim 读数已作废");
        }

        Observation baseline = null;
        Map<String, String> values = new LinkedHashMap<>();
        int acceptedVectors = 0;
        for (Observation row : rows) {
            if (row == null) continue;
            values.put(row.name, row.bucket());
            if ("V0".equals(row.name)) baseline = row;
            if (row.success) {
                acceptedVectors++;
            }
        }
        // A single accepted malformed vector occurs on otherwise clean vendor KeyMint builds.
        // Require a repeat across independent vector shapes; this keeps the probe useful without
        // treating one permissive parser path as a device-wide invariant violation.
        if (acceptedVectors >= 2) {
            return new Decision(DETECTED,
                    "多个包含类型错配 KeyParameter 的原始 generateKey 请求被接受：count="
                            + acceptedVectors + "；读数=" + values);
        }
        if (acceptedVectors == 1) {
            return new Decision(WARNING,
                    "单个类型错配 KeyParameter 请求被接受，但未形成可重复的 TeeSim 证据；"
                            + "该行为可能来自厂商 KeyMint 兼容性差异；读数=" + values);
        }
        if (baseline == null || baseline.serviceCode == null) {
            return new Decision(UNAVAILABLE, "V0 非法 tag 基线没有稳定服务错误码；读数=" + values);
        }

        boolean differential = false;
        for (Observation row : rows) {
            if (row != null && !"V0".equals(row.name)
                    && row.serviceCode != null
                    && !row.serviceCode.equals(baseline.serviceCode)) {
                differential = true;
                break;
            }
        }
        if (differential) {
            // The upstream project labels V0..V4 as measurement-only. Its V5 attribution leg is
            // intentionally omitted because it has repeatedly broken clean devices. Do not turn
            // an unattributed differential into a positive verdict.
            return new Decision(VERIFIED,
                    "观察到已执行向量的错误码差分；安全版本不运行会损坏设备的 V5 归因腿，"
                            + "因此该读数保持中性；读数=" + values);
        }
        return new Decision(VERIFIED, "已执行向量均被非法 tag 路径拒绝；读数=" + values);
    }

    static Decision attestKeyDescriptorDelegation(boolean sourceGenerated,
                                                   boolean sourceDescriptorValid,
                                                   boolean delegatedGenerated,
                                                   long delegatedKeyId,
                                                   boolean invalidAttestKeyAlias,
                                                   boolean cleanupVerified) {
        if (!cleanupVerified) {
            return new Decision(UNAVAILABLE, "直接委派探针的临时密钥未能完整清理");
        }
        if (!sourceGenerated) {
            return new Decision(UNAVAILABLE, "PURPOSE_ATTEST_KEY 源密钥未成功生成");
        }
        if (!sourceDescriptorValid) {
            return new Decision(UNAVAILABLE, "AttestKey 没有返回可用的 KEY_ID 描述符");
        }
        if (invalidAttestKeyAlias) {
            return new Decision(DETECTED,
                    "有效 AttestKey 描述符直接委派时被报告为 Invalid attestKeyAlias");
        }
        if (delegatedGenerated && isUsableKeyId(delegatedKeyId)) {
            return new Decision(VERIFIED,
                    "直接委派成功并返回有效随机 keyId=" + delegatedKeyId);
        }
        return new Decision(UNAVAILABLE,
                delegatedGenerated
                        ? "直接委派完成，但签名密钥返回了保留的未分配 keyId=-1"
                        : "直接委派未完成，错误不符合可确认的 Invalid attestKeyAlias 特征");
    }

    static boolean isUsableKeyId(long keyId) {
        // Keystore2 allocates database IDs from a random signed i64. Positive, zero, and
        // negative values are valid; only -1 is reserved as UNASSIGNED_KEY_ID.
        return keyId != -1L;
    }
}
