import 'dart:convert';
import 'dart:io';

import '../config/adapter_config.dart';

const sentinelEvidenceEnvironment = 'DESIGN_SYSTEM_GUARDIAN_SENTINEL_EVIDENCE';

final class GuardianSentinelExpectation {
  const GuardianSentinelExpectation({
    required this.requestId,
    required this.kind,
    required this.kindIdentity,
    required this.policyDigest,
  });

  final String requestId;
  final String kind;
  final String kindIdentity;
  final String policyDigest;
}

final class GuardianSentinelEvidence {
  const GuardianSentinelEvidence._(this.isValid, this.reason, this.entries);

  factory GuardianSentinelEvidence.invalid(String reason) =>
      GuardianSentinelEvidence._(
        false,
        reason,
        const <GuardianSentinelExpectation>[],
      );

  factory GuardianSentinelEvidence.valid(
    List<GuardianSentinelExpectation> entries,
  ) => GuardianSentinelEvidence._(
    true,
    null,
    List<GuardianSentinelExpectation>.unmodifiable(entries),
  );

  final bool isValid;
  final String? reason;
  final List<GuardianSentinelExpectation> entries;

  bool matches({
    required String requestId,
    required String kindIdentity,
    required String policyDigest,
  }) =>
      isValid &&
      entries.any(
        (entry) =>
            entry.requestId == requestId &&
            entry.kindIdentity == kindIdentity &&
            entry.policyDigest == policyDigest,
      );
}

final class GuardianSentinelEvidenceRepository {
  GuardianSentinelEvidenceRepository._();

  static GuardianSentinelEvidence load(GuardianAdapterConfig config) {
    final path = Platform.environment[sentinelEvidenceEnvironment];
    if (path == null || path.isEmpty || path.trim() != path) {
      return GuardianSentinelEvidence.invalid(
        'missing $sentinelEvidenceEnvironment host binding',
      );
    }
    Object? decoded;
    try {
      decoded = jsonDecode(File(path).readAsStringSync());
    } on Object catch (error) {
      return GuardianSentinelEvidence.invalid(
        'sentinel evidence is unreadable: $error',
      );
    }
    if (decoded is! Map<String, dynamic> ||
        !_hasExactKeys(decoded, <String>{
          'schemaVersion',
          'configDigest',
          'policyDigest',
          'sentinels',
        }) ||
        decoded['schemaVersion'] != 1 ||
        decoded['configDigest'] != config.configDigest ||
        decoded['policyDigest'] != config.policyDigest ||
        decoded['sentinels'] is! List) {
      return GuardianSentinelEvidence.invalid(
        'sentinel evidence is not bound to configDigest and policyDigest',
      );
    }

    final entries = <GuardianSentinelExpectation>[];
    final seen = <String>{};
    String? previous;
    for (final raw in decoded['sentinels'] as List) {
      if (raw is! Map<String, dynamic> ||
          !_hasExactKeys(raw, <String>{
            'requestId',
            'kind',
            'kindIdentity',
            'policyDigest',
          })) {
        return GuardianSentinelEvidence.invalid(
          'sentinel entry shape is invalid',
        );
      }
      final requestId = raw['requestId'];
      final kind = raw['kind'];
      final kindIdentity = raw['kindIdentity'];
      final policyDigest = raw['policyDigest'];
      if (requestId is! String ||
          requestId.isEmpty ||
          kind is! String ||
          kind.isEmpty ||
          kindIdentity is! String ||
          kindIdentity.isEmpty ||
          policyDigest != config.policyDigest) {
        return GuardianSentinelEvidence.invalid(
          'sentinel entry values are invalid',
        );
      }
      final ordering = '$requestId\u0000$kind';
      if ((previous != null && ordering.compareTo(previous) <= 0) ||
          !seen.add(ordering)) {
        return GuardianSentinelEvidence.invalid(
          'sentinel entries must be unique and sorted',
        );
      }
      previous = ordering;
      entries.add(
        GuardianSentinelExpectation(
          requestId: requestId,
          kind: kind,
          kindIdentity: kindIdentity,
          policyDigest: policyDigest as String,
        ),
      );
    }
    return GuardianSentinelEvidence.valid(entries);
  }
}

bool _hasExactKeys(Map<String, dynamic> value, Set<String> expected) =>
    value.keys.toSet().length == expected.length &&
    value.keys.toSet().containsAll(expected);
