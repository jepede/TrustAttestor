package com.lingqing.trustattestor;

import java.util.ArrayList;
import java.util.List;

import static com.lingqing.trustattestor.SilentProbeEvidence.Status.DETECTED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.UNAVAILABLE;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.VERIFIED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.WARNING;

/** Standalone regression tests: run main; no Android runtime or JUnit required. */
public final class OmkRiskyProbeEvidenceTest {
    private static int assertions;

    public static void main(String[] args) {
        tokenMatrixRequiresDescriptorAndCodeEvidence();
        sameCodeTokenLegClassification();
        syntheticOperationDiffSurvivesFullMatrix();
        fingerprintNeedsTagMapAndMissingTaTags();
        backendProvenanceIsIndependentAndSourceBounded();
        uniformVendorFallbackIsCleanShape();
        ambiguousCompleteFingerprintIsNeutral();
        incompletePrivateAbiFingerprintIsNotApplicable();
        riskyProbeTimeoutsAreBounded();
        teeSimDifferentialRemainsNeutralWithoutDangerousV5();
        teeSimBoundedPrefixIsACompletedNeutralObservation();
        teeSimCleanupFailureInvalidatesEvidence();
        acceptingPoisonedGenerateIsDirectFailure();
        attestKeyDescriptorDelegationRequiresValidPrerequisites();
        System.out.println("OmkRiskyProbeEvidenceTest: " + assertions + " assertions passed");
    }

    private static OmkRiskyProbeEvidence.Observation code(String name, int code) {
        return new OmkRiskyProbeEvidence.Observation(name, code, false, "code=" + code, 1000);
    }

    private static OmkRiskyProbeEvidence.Observation backend(String name, int code,
                                                               OmkRiskyProbeEvidence.Observation.BackendSource source) {
        String marker = source == OmkRiskyProbeEvidence.Observation.BackendSource.OMK
                ? "src\\keymaster\\security_level.rs:123"
                : "system/security/keystore2/src/security_level.rs:456";
        return new OmkRiskyProbeEvidence.Observation(name, code, false,
                "ServiceSpecificException code=" + code + " at " + marker, 1000, source);
    }

    private static void tokenMatrixRequiresDescriptorAndCodeEvidence() {
        OmkRiskyProbeEvidence.TokenReply before = captured("getNumberOfEntries", "correct", 101, true, ints(0, 7));
        OmkRiskyProbeEvidence.TokenReply after = captured("getNumberOfEntries", "correct", 101, true, ints(0, 7));
        OmkRiskyProbeEvidence.TokenReply other = captured("listEntries", "correct", 102, true, ints(0, 9));
        OmkRiskyProbeEvidence.TokenReply wrongA = captured("getNumberOfEntries",
                "android.security.maintenance.IKeystoreMaintenance", 101, false, ints(-8, 0, 0, 0, 0));
        OmkRiskyProbeEvidence.TokenReply wrongB = captured("listEntries",
                "android.security.maintenance.IKeystoreMaintenance", 102, false, ints(-8, 0, 0, 0, 0));
        OmkRiskyProbeEvidence.TokenReply randomReject = captured("getNumberOfEntries", "random", 101, false, ints(-1, 0, 0, 0));
        List<OmkRiskyProbeEvidence.TokenReply> repeated = List.of(
                before, other, wrongA, wrongA, wrongB, wrongB, randomReject);
        check(passive(repeated, before, after).status == DETECTED,
                "repeated anomalies at two controlled transactions with random rejection are detected");
        check(passive(List.of(before, other, wrongA, wrongB, randomReject), before, after).status == WARNING,
                "unrepeated cross-method differences are insufficient");
        check(passive(List.of(before, other, wrongA, wrongA, wrongB, wrongB), before, after).status == WARNING,
                "missing random rejection control is insufficient");
        check(passive(List.of(before, wrongA, wrongA, randomReject), before, after).status == WARNING,
                "one repeated transaction is insufficient");
        check(passive(List.of(before, randomReject), before, after).status == VERIFIED,
                "complete security rejection is compatible with expected behavior");
        OmkRiskyProbeEvidence.TokenReply numberControl = captured(
                "getNumberOfEntries", "correct", 108, true, ints(0, 0));
        OmkRiskyProbeEvidence.TokenReply safeMaintenanceReject = captured(
                "getNumberOfEntries", "android.security.maintenance.IKeystoreMaintenance",
                108, false, ints(-1, 0, 0, 0));
        check(passive(List.of(before, numberControl, safeMaintenanceReject,
                safeMaintenanceReject), before, after).status == VERIFIED,
                "clean descriptor rejection remains verified");
        OmkRiskyProbeEvidence.TokenReply omkTransportFailure = new OmkRiskyProbeEvidence.TokenReply(
                "getNumberOfEntries", "android.security.maintenance.IKeystoreMaintenance", 108,
                false, false, Integer.MIN_VALUE + 1, null, null, null);
        check(passive(List.of(before, numberControl, omkTransportFailure,
                omkTransportFailure), before, after).status == WARNING,
                "repeated maintenance transport failure is inconclusive only");
        OmkRiskyProbeEvidence.TokenReply omkBusinessReply = captured(
                "getNumberOfEntries", "android.security.maintenance.IKeystoreMaintenance",
                108, false, ints(-8, 0, 0, 0, 0));
        check(passive(List.of(before, numberControl, omkBusinessReply,
                omkBusinessReply), before, after).status == WARNING,
                "one-code maintenance business replies are insufficient");
        check(OmkRiskyProbeEvidence.tokenDispatch(new OmkRiskyProbeEvidence.TokenDispatchInput(
                true, true, 0, List.of(before, randomReject), before, after, false, true))
                .status == VERIFIED, "runtime Stub table remains valid when version is unavailable");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, true, true, false, true,
                8, "getNumberOfEntries", null).status == VERIFIED,
                "same-code service control plus reflected transport failure is neutral");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, true, true, true, true,
                7, "listEntries", new OmkRiskyProbeEvidence.ParsedStatus(
                        4, 0, null, true, true)).status == VERIFIED,
                "same-code service control plus reflected reply remains clean");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, true, true, true, true,
                8, "getNumberOfEntries", new OmkRiskyProbeEvidence.ParsedStatus(
                        20, -8, 0, true, true)).status == DETECTED,
                "OMK service-specific reply remains a detected token anomaly");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, true, true, true, true,
                8, "getNumberOfEntries", new OmkRiskyProbeEvidence.ParsedStatus(
                        532, -8, 7, true, true)).status == DETECTED,
                "documented KEY_NOT_FOUND business reply remains a detected token anomaly");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, false, false, true, false, true,
                8, "getNumberOfEntries", null).status == VERIFIED,
                "missing same-code control is neutral on a clean-looking device");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("getSecurityLevel", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(8, 0, null,
                                true, false), true),
                new OmkRiskyProbeEvidence.TrailingReply("getSecurityLevel", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(8, -9, null,
                                true, true), false))).status == VERIFIED,
                "clean AIDL Stub rejection of trailing data remains verified");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("listEntries", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(20, -8, 7,
                                true, true), false),
                new OmkRiskyProbeEvidence.TrailingReply("listEntries", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(32, 0, null,
                                true, false), false))).status == DETECTED,
                "tail-only successful reply change is detected");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("listEntries", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(32, 0, null,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("listEntries", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(32, 0, null,
                                true, false), false))).status == VERIFIED,
                "unchanged successful clean and tail replies are verified");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("getKeyEntry", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(20, -8, 7,
                                true, true), false),
                new OmkRiskyProbeEvidence.TrailingReply("getKeyEntry", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(20, -8, 0,
                                true, true), false))).status == DETECTED,
                "OMK service-specific reply with trailing data is detected");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("getKeyEntry", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(20, -8, 0,
                                true, true), false),
                new OmkRiskyProbeEvidence.TrailingReply("getKeyEntry", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(20, -8, 7,
                                true, true), false))).status == DETECTED,
                "any tail-only ServiceSpecific code change is detected");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("syntheticSecurityLevel.deleteKey", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(20, -8, 7,
                                true, true), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticSecurityLevel.deleteKey", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(20, -8, 0,
                                true, true), false))).status == DETECTED,
                "synthetic SecurityLevel OMK reply with trailing data is detected");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(368, -8, -40,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(20, -8, -28,
                                 true, true), false))).status == VERIFIED,
                 "legacy invalid EC Operation lifecycle is not a tail finding");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(4, 0, null,
                                true, true), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(20, -8, -28,
                                true, true), false))).status == DETECTED,
                "valid GCM Operation tail-only invalid-handle reply is detected");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(4, 0, null,
                                true, true), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(4, 0, null,
                                true, true), false))).status == DETECTED,
                "valid GCM Operation tail success is detected even when its length is unchanged");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(4, 0, null,
                                true, true), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(4, -9, null,
                                true, true), false))).status == VERIFIED,
                "strict AOSP Operation tail rejection remains verified");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(408, -8, -38,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(304, -8, -28,
                                true, false), false))).status == VERIFIED,
                "normal Operation error-shape change without a status-only reply is verified");
        check(OmkRiskyProbeEvidence.trailingData(null).status == UNAVAILABLE,
                "missing trailing-data matrix is unavailable");
        check(passive(List.of(before), before, after).status == UNAVAILABLE,
                "metadata and correct replies alone cannot prove a clean token boundary");
        check(passive(repeated, before, wrongA).status == UNAVAILABLE,
                "incorrect after control invalidates the evidence");
        check(passive(repeated, before, other).status == UNAVAILABLE,
                "before and after must be the same transaction");
        check(OmkRiskyProbeEvidence.tokenDispatch(new OmkRiskyProbeEvidence.TokenDispatchInput(
                false, true, 3, repeated, before, after, false, true)).status == UNAVAILABLE,
                "unverified endpoint invalidates evidence");
        check(OmkRiskyProbeEvidence.tokenDispatch(new OmkRiskyProbeEvidence.TokenDispatchInput(
                true, false, 3, repeated, before, after, false, true)).status == UNAVAILABLE,
                "unverified version invalidates evidence");
        check(OmkRiskyProbeEvidence.tokenDispatch(new OmkRiskyProbeEvidence.TokenDispatchInput(
                true, true, 3, repeated, before, after, false, false)).status == UNAVAILABLE,
                "failed cleanup invalidates evidence");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, true, false, false, true,
                8, "getNumberOfEntries", null).status == VERIFIED,
                "locally unmarshalable migration request is neutral instead of unfinished");
        check(OmkRiskyProbeEvidence.tokenDispatch(null).status == UNAVAILABLE,
                "missing matrix is unavailable");
        check(wrongA.status.exceptionCode == -8 && wrongA.status.serviceSpecificCode == 0,
                "exception and service-specific numbering are separate");
        check(wrongA.binderStatus == null && wrongA.replyFlags == null && wrongA.offsetsSizeBytes == null,
                "unexposed native metadata remains unknown");
        check(wrongA.rawDigest.length() == 64, "captured bytes have a full SHA-256 digest");

        OmkRiskyProbeEvidence.TokenReply rawTypeReject = new OmkRiskyProbeEvidence.TokenReply(
                "readA", "random", 101, false, true, null, null, null, ints(-1, 0, 0, 0));
        check(passive(List.of(before, rawTypeReject), before, after).status == VERIFIED,
                "native BAD_TYPE is compatible with descriptor rejection");
        OmkRiskyProbeEvidence.TokenReply rawStatus = new OmkRiskyProbeEvidence.TokenReply(
                "readA", "other", 101, false, true, 0, 8, 0L, ints(-8, 0, 0, 0, 41));
        check(passive(List.of(before, rawStatus), before, after).status == WARNING,
                "TF_STATUS_CODE cannot be decoded as an AIDL business reply");
        check(passive(List.of(before, captured("readA", "other", 101, false, ints(-8))), before, after)
                .status == WARNING, "truncated reply is inconclusive instead of detected");
        check(passive(List.of(before, captured("readA", "other", 101, false, ints(0, 1, 2, 3, 4))), before, after)
                .status == WARNING, "a 20-byte reply alone is insufficient");
        check(passive(List.of(before, captured("readA", "other", 101, false, ints(-7, 0, 0, 0))), before, after)
                .status == WARNING, "a parseable nonbusiness exception alone is insufficient");
        OmkRiskyProbeEvidence.TokenReply optionalTransportReject = new OmkRiskyProbeEvidence.TokenReply(
                "listEntries", "other", 102, false, false, Integer.MIN_VALUE + 1,
                null, null, null);
        check(passive(List.of(before, randomReject, optionalTransportReject), before, after)
                .status == VERIFIED, "optional transport rejection does not invalidate a clean matrix");
        OmkRiskyProbeEvidence.TokenReply coreTransportReject = new OmkRiskyProbeEvidence.TokenReply(
                "getKeyEntry", "other", 101, false, false, Integer.MIN_VALUE + 1,
                null, null, null);
        check(passive(List.of(before, randomReject, coreTransportReject), before, after)
                .status == WARNING, "core transport rejection remains explicitly inconclusive");
        check(OmkRiskyProbeEvidence.tokenDispatch(new OmkRiskyProbeEvidence.TokenDispatchInput(
                true, true, 3, List.of(before, randomReject), before, after, true, true))
                .status == WARNING, "recovery differences without a fresh-connection control stay inconclusive");
        statusParserRejectsMalformedEnvelopes();
    }

    private static void sameCodeTokenLegClassification() {
        OmkRiskyProbeEvidence.TokenLeg service = leg(true, true, true,
                new OmkRiskyProbeEvidence.ParsedStatus(20, -8, 7, true, true),
                "reply", null);
        OmkRiskyProbeEvidence.TokenLeg cleanReject = leg(true, true, true,
                new OmkRiskyProbeEvidence.ParsedStatus(16, -1, null, true, true),
                "reply", null);
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, 7, "ungrant",
                service, cleanReject, cleanReject, cleanReject).status == VERIFIED,
                "same-code standard rejection remains verified");

        OmkRiskyProbeEvidence.TokenLeg illegalArgument = leg(true, true, false, null,
                "transact", "java.lang.IllegalArgumentException");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, 7, "ungrant",
                service, cleanReject, illegalArgument, illegalArgument).status == DETECTED,
                "repeatable maintenance-only IllegalArgumentException is detected");

        OmkRiskyProbeEvidence.TokenLeg unknownTransport = leg(true, true, false, null,
                "transact", "android.os.RemoteException");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, 7, "ungrant",
                service, cleanReject, unknownTransport, unknownTransport).status == WARNING,
                "other maintenance-only transport differences remain warning");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, 7, "ungrant",
                service, cleanReject, new OmkRiskyProbeEvidence.TokenLeg(
                        false, false, false, null, "source-descriptor", null, null, 4, 0),
                null).status == WARNING,
                "unmarshalled maintenance request remains warning");
    }

    private static OmkRiskyProbeEvidence.TokenLeg leg(boolean parcelBuilt, boolean entered,
                                                       boolean answered,
                                                       OmkRiskyProbeEvidence.ParsedStatus status,
                                                       String phase, String failureClass) {
        return new OmkRiskyProbeEvidence.TokenLeg(parcelBuilt, entered, answered, status,
                phase, failureClass, null, 64, answered ? 20 : 0);
    }

    private static void syntheticOperationDiffSurvivesFullMatrix() {
        // Reproduce the OMK log shape: getSecurityLevel is excluded by the runtime probe,
        // listEntries is identical on both legs, and only the synthetic Operation tail is
        // shortened to the -28 service-specific status.
        List<OmkRiskyProbeEvidence.TrailingReply> rows = List.of(
                new OmkRiskyProbeEvidence.TrailingReply("getKeyEntry", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(492, -8, 7,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("getKeyEntry", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(492, -8, 7,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("listEntries", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(304, 0, null,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("listEntries", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(304, 0, null,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticSecurityLevel.deleteKey", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(256, -8, -38,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticSecurityLevel.deleteKey", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(256, -8, -38,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(368, -8, -40,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(20, -8, -28,
                                true, false), false));
         check(OmkRiskyProbeEvidence.trailingData(rows).status == VERIFIED,
                 "legacy invalid Operation differential remains neutral in the complete matrix");
        check(OmkRiskyProbeEvidence.trailingData(List.of(
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", false,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(368, -8, -40,
                                true, false), false),
                new OmkRiskyProbeEvidence.TrailingReply("syntheticOperation.updateAad", true,
                        true, true, new OmkRiskyProbeEvidence.ParsedStatus(64, -8, -28,
                         true, false), false))).status == VERIFIED,
                 "short invalid Operation envelope remains neutral without a successful clean leg");
    }

    private static OmkRiskyProbeEvidence.Decision passive(List<OmkRiskyProbeEvidence.TokenReply> rows,
                                                           OmkRiskyProbeEvidence.TokenReply before,
                                                           OmkRiskyProbeEvidence.TokenReply after) {
        return OmkRiskyProbeEvidence.tokenDispatch(new OmkRiskyProbeEvidence.TokenDispatchInput(
                true, true, 3, rows, before, after, false, true));
    }

    private static OmkRiskyProbeEvidence.TokenReply captured(String method, String token, int transaction,
                                                             boolean expected, byte[] raw) {
        return new OmkRiskyProbeEvidence.TokenReply(method, token, transaction, expected,
                true, null, null, null, raw);
    }

    private static byte[] ints(int... values) {
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(values.length * 4)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN);
        for (int value : values) buffer.putInt(value);
        return buffer.array();
    }

    private static void statusParserRejectsMalformedEnvelopes() {
        check(!OmkRiskyProbeEvidence.parseStatus(null).valid, "missing bytes are incomplete");
        check(!OmkRiskyProbeEvidence.parseStatus(new byte[0]).valid, "empty bytes are incomplete");
        check(!OmkRiskyProbeEvidence.parseStatus(new byte[5]).valid, "unaligned envelope is incomplete");
        check(!OmkRiskyProbeEvidence.parseStatus(ints(-8, Integer.MAX_VALUE)).valid,
                "oversized String16 length cannot overflow");
        check(!OmkRiskyProbeEvidence.parseStatus(ints(-8, -2, 0, 0)).valid,
                "invalid negative String16 length is rejected");
        check(!OmkRiskyProbeEvidence.parseStatus(ints(-8, 0, 1, 0, 41)).valid,
                "unterminated String16 is rejected");
        check(!OmkRiskyProbeEvidence.parseStatus(ints(-8, 0, 0, -1, 41)).valid,
                "negative stack header is rejected");
        check(!OmkRiskyProbeEvidence.parseStatus(ints(-8, 0, 0, Integer.MAX_VALUE, 41)).valid,
                "oversized stack header is rejected");
        check(!OmkRiskyProbeEvidence.parseStatus(ints(-8, 0, 0, 0)).valid,
                "missing business error is rejected");
        check(!OmkRiskyProbeEvidence.parseStatus(ints(-128, 0)).valid,
                "unsupported extended header is incomplete rather than abnormal");
        check(!OmkRiskyProbeEvidence.parseStatus(ints(-129)).valid,
                "native transaction status cannot be interpreted as AIDL Status");
        check(OmkRiskyProbeEvidence.parseStatus(ints(-9, -1, 0, 0)).valid,
                "BadParcelableException rejection is a valid AIDL envelope");
        OmkRiskyProbeEvidence.ParsedStatus nonempty = OmkRiskyProbeEvidence.parseStatus(ints(-8, 1, 'x', 0, 99));
        check(nonempty.valid && nonempty.serviceSpecificCode == 99,
                "message character count is not a business error code");
        OmkRiskyProbeEvidence.ParsedStatus nullMessage = OmkRiskyProbeEvidence.parseStatus(ints(-8, -1, 0, 99));
        check(nullMessage.valid && nullMessage.serviceSpecificCode == 99, "null message is supported");
        OmkRiskyProbeEvidence.ParsedStatus withStack = OmkRiskyProbeEvidence.parseStatus(ints(-8, 0, 0, 8, 0, 99));
        check(withStack.valid && withStack.serviceSpecificCode == 99, "sized stack header is skipped");
        OmkRiskyProbeEvidence.ParsedStatus trailing = OmkRiskyProbeEvidence.parseStatus(ints(-8, 0, 0, 0, 99, 7));
        check(trailing.valid && !trailing.statusOnly, "extra payload prevents Status-only classification");
        check(OmkRiskyProbeEvidence.parseStatus(ints(-128, 8, 123, 0)).statusOnly,
                "fat StrictMode reply header is consumed before the AIDL status");
    }
    private static void fingerprintNeedsTagMapAndMissingTaTags() {
        List<OmkRiskyProbeEvidence.Observation> rows = List.of(
                backend("ALGORITHM+Integer", -4,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2),
                backend("ALGORITHM+Blob", -4,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2),
                backend("BLOCK_MODE+Integer", -7,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2),
                backend("BLOCK_MODE+Blob", -7,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2),
                backend("DIGEST+Integer", -10,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2),
                backend("DIGEST+Blob", -10,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2));
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, true, rows, false).status == VERIFIED,
                "standard AOSP tag mappings plus absent TA tags remain verified");
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, true, rows, true).status == VERIFIED,
                "TA tags are contextual and do not change the clean classification");
        List<OmkRiskyProbeEvidence.Observation> omk = new ArrayList<>(rows);
        for (int i = 0; i < omk.size(); i++) {
            OmkRiskyProbeEvidence.Observation row = omk.get(i);
            omk.set(i, backend(row.name, row.serviceCode,
                    OmkRiskyProbeEvidence.Observation.BackendSource.OMK));
        }
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, true, omk, false).status == VERIFIED,
                "OMK source is reported by the independent backend finding, not this heuristic");
        List<OmkRiskyProbeEvidence.Observation> accepted = new ArrayList<>(rows);
        accepted.set(0, new OmkRiskyProbeEvidence.Observation(
                "ALGORITHM+Integer", null, true, "success(operation=none)", 1000,
                OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2));
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, true, accepted, false).status == WARNING,
                "an accepted malformed operation remains a warning");
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, false, rows, false).status == UNAVAILABLE,
                "failed post-canary invalidates a would-be hit");
    }

    private static void backendProvenanceIsIndependentAndSourceBounded() {
        List<OmkRiskyProbeEvidence.Observation> omk = List.of(
                backend("ALGORITHM+Integer", -4,
                        OmkRiskyProbeEvidence.Observation.BackendSource.OMK),
                backend("ALGORITHM+Blob", -4,
                        OmkRiskyProbeEvidence.Observation.BackendSource.OMK),
                backend("BLOCK_MODE+Integer", -7,
                        OmkRiskyProbeEvidence.Observation.BackendSource.OMK),
                backend("BLOCK_MODE+Blob", -7,
                        OmkRiskyProbeEvidence.Observation.BackendSource.OMK),
                backend("DIGEST+Integer", -10,
                        OmkRiskyProbeEvidence.Observation.BackendSource.OMK),
                backend("DIGEST+Blob", -10,
                        OmkRiskyProbeEvidence.Observation.BackendSource.OMK));
        check(OmkRiskyProbeEvidence.backendProvenance(true, true, omk).status == DETECTED,
                "six stable OMK backend source rows are an independent finding");
        check(OmkRiskyProbeEvidence.classifyBackendSource(
                        "C:\\any\\checkout\\src\\keymaster\\security_level.rs:1")
                        == OmkRiskyProbeEvidence.Observation.BackendSource.OMK,
                "OMK classification ignores the absolute checkout prefix");

        List<OmkRiskyProbeEvidence.Observation> aosp = List.of(
                backend("ALGORITHM+Integer", -21,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2),
                backend("ALGORITHM+Blob", -21,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2),
                backend("BLOCK_MODE+Integer", -21,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2),
                backend("BLOCK_MODE+Blob", -21,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2),
                backend("DIGEST+Integer", -21,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2),
                backend("DIGEST+Blob", -21,
                        OmkRiskyProbeEvidence.Observation.BackendSource.AOSP_KEYSTORE2));
        check(OmkRiskyProbeEvidence.backendProvenance(true, true, aosp).status == VERIFIED,
                "six stable Keystore2 backend source rows are verified");

        List<OmkRiskyProbeEvidence.Observation> mixed = new ArrayList<>(omk);
        mixed.set(5, aosp.get(5));
        check(OmkRiskyProbeEvidence.backendProvenance(true, true, mixed).status == WARNING,
                "mixed backend source rows are not attributed to OMK");
        check(OmkRiskyProbeEvidence.backendProvenance(true, true,
                        List.of(code("ALGORITHM+Integer", -4))).status == UNAVAILABLE,
                "a shortened parameter matrix cannot establish backend provenance");
        List<OmkRiskyProbeEvidence.Observation> completedWithAcceptance = new ArrayList<>(omk);
        completedWithAcceptance.set(0,
                new OmkRiskyProbeEvidence.Observation("ALGORITHM+Integer", null,
                        true, "success(operation=none)", 1000));
        check(OmkRiskyProbeEvidence.backendProvenance(true, true,
                        completedWithAcceptance).status == WARNING,
                "a completed matrix with one accepted malformed request is not unfinished");
        check(OmkRiskyProbeEvidence.backendProvenance(false, true, omk).status == UNAVAILABLE,
                "failed pre-canary keeps backend provenance unavailable");
    }

    private static void uniformVendorFallbackIsCleanShape() {
        List<OmkRiskyProbeEvidence.Observation> rows = new ArrayList<>();
        for (int i = 0; i < 10; i++) rows.add(code("v" + i, -21));
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, true, rows, null).status == VERIFIED,
                "uniform vendor fallback is a completed non-hit");
    }

    private static void ambiguousCompleteFingerprintIsNeutral() {
        List<OmkRiskyProbeEvidence.Observation> rows = new ArrayList<>();
        for (int i = 0; i < 10; i++) rows.add(code("v" + i, -38));
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, true, rows, null).status == VERIFIED,
                "an ambiguous but complete fingerprint is not an execution failure");
    }

    private static void incompletePrivateAbiFingerprintIsNotApplicable() {
        check(OmkRiskyProbeEvidence.parameterFingerprint(
                        true, true, List.of(code("ALGORITHM+Integer", -4)), null).status == VERIFIED,
                "an OEM private ABI that cannot supply six vectors is neutral");
    }

    private static void riskyProbeTimeoutsAreBounded() {
        check(OmkRiskyProbes.PARAMETER_FINGERPRINT_TIMEOUT_SECONDS <= 12,
                "KeyMint parameter fingerprint is capped at twelve seconds");
        check(OmkRiskyProbes.TEESIM_TIMEOUT_SECONDS <= 10,
                "TeeSim fingerprint is capped at ten seconds");
    }

    private static void teeSimDifferentialRemainsNeutralWithoutDangerousV5() {
        List<OmkRiskyProbeEvidence.Observation> rows = List.of(
                code("V0", -21), code("V1", -38), code("V2", -21));
        check(OmkRiskyProbeEvidence.teeSimFingerprint(true, true, rows, false).status == VERIFIED,
                "unattributed V0-V4 differential remains neutral");
    }

    private static void acceptingPoisonedGenerateIsDirectFailure() {
        List<OmkRiskyProbeEvidence.Observation> rows = List.of(
                code("V0", -21),
                new OmkRiskyProbeEvidence.Observation("V1", null, true, "success", 1000));
        check(OmkRiskyProbeEvidence.teeSimFingerprint(true, true, rows, false).status == WARNING,
                "one accepted type-confused generate request is only a warning");
        List<OmkRiskyProbeEvidence.Observation> repeated = List.of(
                new OmkRiskyProbeEvidence.Observation("V0", null, true, "success", 1000),
                new OmkRiskyProbeEvidence.Observation("V1", null, true, "success", 1000));
        check(OmkRiskyProbeEvidence.teeSimFingerprint(true, true, repeated, false).status == DETECTED,
                "repeated accepted type-confused generate requests are detected");
    }

    private static void teeSimBoundedPrefixIsACompletedNeutralObservation() {
        check(OmkRiskyProbeEvidence.teeSimFingerprint(
                        true, true, List.of(code("V0", -21)), false).status == VERIFIED,
                "a valid bounded V0 prefix is neutral instead of unavailable");
    }

    private static void teeSimCleanupFailureInvalidatesEvidence() {
        check(OmkRiskyProbeEvidence.teeSimFingerprint(
                        true, true, List.of(code("V0", -21)), true).status == UNAVAILABLE,
                "cleanup failure still invalidates the TeeSim observation");
    }

    private static void attestKeyDescriptorDelegationRequiresValidPrerequisites() {
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, true, 42L, false, true).status == VERIFIED,
                "direct delegation with a positive key ID is verified");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, false, 0L, true, true).status == DETECTED,
                "exact invalid-attest-alias rejection after valid setup is detected");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        false, false, false, 0L, true, true).status == UNAVAILABLE,
                "an alias error without a generated source key is unavailable");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, false, false, 0L, true, true).status == UNAVAILABLE,
                "an alias error with an invalid source descriptor is unavailable");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, false, 0L, false, true).status == UNAVAILABLE,
                "unclassified delegation failures are unavailable");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, true, 42L, false, false).status == UNAVAILABLE,
                "cleanup failure invalidates an otherwise successful result");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, true, 0L, false, true).status == VERIFIED,
                "zero key ID is a valid randomized database ID");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, true, -42L, false, true).status == VERIFIED,
                "negative randomized key ID is valid");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, true, -1L, false, true).status == UNAVAILABLE,
                "reserved unassigned key ID is not successful");
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}
