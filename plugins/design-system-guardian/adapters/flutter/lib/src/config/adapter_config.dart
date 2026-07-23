import 'dart:convert';
import 'dart:io';

import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:crypto/crypto.dart';

const _adapterConfigDirectory = '.design-system-guardian';
const _adapterConfigFile = 'flutter-adapter.json';
const _adapterConfigEnvironment = 'DESIGN_SYSTEM_GUARDIAN_FLUTTER_CONFIG';
const _adapterVersion = '0.1.0';
const _identityCategories = <String>{
  'colors',
  'textStyles',
  'icons',
  'dimensions',
  'effects',
  'motion',
  'widgets',
};

enum ConfigBindingStatus { valid, invalid, unbound }

/// Fail-closed result used by every rule. A rule must never infer a fallback
/// catalog when [status] is not [ConfigBindingStatus.valid].
final class ConfigBinding {
  const ConfigBinding._(this.status, this.config, this.reason);

  factory ConfigBinding.valid(GuardianAdapterConfig config) =>
      ConfigBinding._(ConfigBindingStatus.valid, config, null);

  factory ConfigBinding.invalid(String reason) =>
      ConfigBinding._(ConfigBindingStatus.invalid, null, reason);

  factory ConfigBinding.unbound(String reason) =>
      ConfigBinding._(ConfigBindingStatus.unbound, null, reason);

  final ConfigBindingStatus status;
  final GuardianAdapterConfig? config;
  final String? reason;

  bool get isValid => status == ConfigBindingStatus.valid && config != null;
}

final class GuardianApprovedPackage {
  const GuardianApprovedPackage({
    required this.contentDigest,
    required this.repositoryCommit,
  });

  final String contentDigest;
  final String repositoryCommit;
}

final class GuardianToolchain {
  const GuardianToolchain({
    required this.platformId,
    required this.contentDigest,
    required this.executableRelativePath,
  });

  final String platformId;
  final String contentDigest;
  final String executableRelativePath;
}

final class GuardianAdapterConfig {
  const GuardianAdapterConfig({
    required this.profileId,
    required this.policyDigest,
    required this.snapshotId,
    required this.sourceCutDigest,
    required this.configDigest,
    required this.toolchain,
    required this.requiredPackages,
    required this.approvedPackages,
    required this.approvedIdentities,
    required this.componentVariants,
  });

  final String profileId;
  final String policyDigest;
  final String snapshotId;
  final String sourceCutDigest;
  final String configDigest;
  final GuardianToolchain toolchain;
  final Map<String, GuardianApprovedPackage> requiredPackages;
  final Map<String, GuardianApprovedPackage> approvedPackages;
  final Map<String, Set<String>> approvedIdentities;
  final Map<String, Map<String, Set<String>>> componentVariants;

  bool isApproved(String category, String? identity) =>
      identity != null && approvedIdentities[category]!.contains(identity);

  Map<String, Set<String>>? variantsFor(String? constructorIdentity) =>
      constructorIdentity == null ? null : componentVariants[constructorIdentity];

  Map<String, String> get binding => <String, String>{
        'profileId': profileId,
        'policyDigest': policyDigest,
        'snapshotId': snapshotId,
        'sourceCutDigest': sourceCutDigest,
        'configDigest': configDigest,
      };
}

/// Loads the generated configuration rooted at the analyzed package. The host
/// Guardian process must also compare the five binding fields with its sealed
/// run manifest; the Dart plugin verifies structure and [configDigest].
final class GuardianAdapterConfigRepository {
  GuardianAdapterConfigRepository._();

  static final Map<String, ({DateTime modified, ConfigBinding binding})> _cache = {};

  static ConfigBinding load(RuleContext context) {
    final environmentPath = Platform.environment[_adapterConfigEnvironment];
    final String configPath;
    if (environmentPath != null && environmentPath.isNotEmpty) {
      if (environmentPath.trim() != environmentPath) {
        return ConfigBinding.invalid(
          '$_adapterConfigEnvironment must not contain surrounding whitespace',
        );
      }
      configPath = environmentPath;
    } else {
      final rootPath = context.package?.root.path;
      if (rootPath == null || rootPath.isEmpty) {
        return ConfigBinding.unbound('analyzed unit is not bound to a package root');
      }
      configPath = <String>[
        rootPath,
        _adapterConfigDirectory,
        _adapterConfigFile,
      ].join(Platform.pathSeparator);
    }
    final file = File(configPath);
    try {
      if (!file.existsSync()) {
        return ConfigBinding.unbound('missing $configPath');
      }
    } on FileSystemException catch (error) {
      return ConfigBinding.invalid('cannot access adapter config: ${error.message}');
    }

    DateTime modified;
    try {
      modified = file.lastModifiedSync().toUtc();
    } on FileSystemException catch (error) {
      return ConfigBinding.invalid('cannot stat adapter config: ${error.message}');
    }
    final cached = _cache[configPath];
    if (cached != null && cached.modified == modified) {
      return cached.binding;
    }
    final binding = _decode(file);
    _cache[configPath] = (modified: modified, binding: binding);
    return binding;
  }

  static ConfigBinding _decode(File file) {
    Object? decoded;
    try {
      decoded = jsonDecode(file.readAsStringSync());
    } on Object catch (error) {
      return ConfigBinding.invalid('adapter config is not valid UTF-8 JSON: $error');
    }
    if (decoded is! Map<String, dynamic>) {
      return ConfigBinding.invalid('adapter config root must be an object');
    }

    final exactTopLevelKeys = <String>{
      'schemaVersion',
      'adapter',
      'adapterVersion',
      'profileId',
      'policyDigest',
      'snapshotId',
      'sourceCutDigest',
      'configDigest',
      'approvedPackages',
      'toolchain',
      'requiredPackages',
      'approvedIdentities',
      'componentVariants',
    };
    if (!_hasExactKeys(decoded, exactTopLevelKeys)) {
      return ConfigBinding.invalid('adapter config keys do not match schema v1');
    }
    if (decoded['schemaVersion'] != 1 ||
        decoded['adapter'] != 'flutter' ||
        decoded['adapterVersion'] != _adapterVersion) {
      return ConfigBinding.invalid('unsupported Flutter adapter schema or version');
    }

    final profileId = decoded['profileId'];
    final policyDigest = decoded['policyDigest'];
    final snapshotId = decoded['snapshotId'];
    final sourceCutDigest = decoded['sourceCutDigest'];
    final configDigest = decoded['configDigest'];
    if (profileId is! String || profileId.isEmpty ||
        policyDigest is! String || !_isDigest(policyDigest) ||
        snapshotId is! String || snapshotId.isEmpty ||
        sourceCutDigest is! String || !_isDigest(sourceCutDigest) ||
        configDigest is! String || !_isDigest(configDigest)) {
      return ConfigBinding.unbound(
        'profileId, policyDigest, snapshotId, sourceCutDigest, and configDigest are mandatory',
      );
    }
    if (!verifyConfigDigest(decoded)) {
      return ConfigBinding.invalid('configDigest does not match canonical config content');
    }

    final rawToolchain = decoded['toolchain'];
    if (rawToolchain is! Map<String, dynamic> ||
        !_hasExactKeys(rawToolchain, <String>{'platformId', 'dartSdk'})) {
      return ConfigBinding.invalid('toolchain must be one exact platform-bound Dart SDK');
    }
    final platformId = rawToolchain['platformId'];
    final rawDartSdk = rawToolchain['dartSdk'];
    const platforms = <String>{
      'windows-x64',
      'windows-arm64',
      'linux-x64',
      'linux-arm64',
      'macos-x64',
      'macos-arm64',
    };
    if (platformId is! String ||
        !platforms.contains(platformId) ||
        rawDartSdk is! Map<String, dynamic> ||
        !_hasExactKeys(rawDartSdk, <String>{'contentDigest', 'executableRelativePath'})) {
      return ConfigBinding.invalid('toolchain Dart SDK binding is malformed');
    }
    final dartSdkDigest = rawDartSdk['contentDigest'];
    final dartExecutable = rawDartSdk['executableRelativePath'];
    final expectedExecutable =
        platformId.startsWith('windows-') ? 'bin/dart.exe' : 'bin/dart';
    if (dartSdkDigest is! String ||
        !_isDigest(dartSdkDigest) ||
        dartExecutable != expectedExecutable) {
      return ConfigBinding.invalid('toolchain executable or content identity is not exact');
    }
    final toolchain = GuardianToolchain(
      platformId: platformId,
      contentDigest: dartSdkDigest,
      executableRelativePath: dartExecutable as String,
    );

    final rawRequiredPackages = decoded['requiredPackages'];
    if (rawRequiredPackages is! Map<String, dynamic> ||
        !rawRequiredPackages.containsKey('flutter')) {
      return ConfigBinding.invalid('requiredPackages must contain exact flutter authority');
    }
    final requiredPackages = <String, GuardianApprovedPackage>{};
    for (final entry in rawRequiredPackages.entries) {
      final value = entry.value;
      if (!_isPackageName(entry.key) ||
          entry.key == 'design_system_guardian_flutter' ||
          value is! Map<String, dynamic> ||
          !_hasExactKeys(value, <String>{'contentDigest', 'repositoryCommit'})) {
        return ConfigBinding.invalid('requiredPackages contains a malformed package');
      }
      final contentDigest = value['contentDigest'];
      final repositoryCommit = value['repositoryCommit'];
      if (contentDigest is! String ||
          !_isDigest(contentDigest) ||
          repositoryCommit is! String ||
          !_isRepositoryCommit(repositoryCommit)) {
        return ConfigBinding.invalid('required package authority is malformed');
      }
      requiredPackages[entry.key] = GuardianApprovedPackage(
        contentDigest: contentDigest,
        repositoryCommit: repositoryCommit,
      );
    }

    final rawPackages = decoded['approvedPackages'];
    if (rawPackages is! Map<String, dynamic>) {
      return ConfigBinding.invalid('approvedPackages must be an object');
    }
    final packages = <String, GuardianApprovedPackage>{};
    for (final entry in rawPackages.entries) {
      final value = entry.value;
      if (!_isPackageName(entry.key) ||
          entry.key == 'flutter' ||
          entry.key == 'design_system_guardian_flutter' ||
          value is! Map<String, dynamic> ||
          !_hasExactKeys(value, <String>{'contentDigest', 'repositoryCommit'})) {
        return ConfigBinding.invalid(
          'approvedPackages contains a malformed or forbidden package',
        );
      }
      final contentDigest = value['contentDigest'];
      final repositoryCommit = value['repositoryCommit'];
      if (contentDigest is! String ||
          !_isDigest(contentDigest) ||
          repositoryCommit is! String ||
          !_isRepositoryCommit(repositoryCommit)) {
        return ConfigBinding.invalid(
          'approved package digest or repository commit is malformed',
        );
      }
      packages[entry.key] = GuardianApprovedPackage(
        contentDigest: contentDigest,
        repositoryCommit: repositoryCommit,
      );
    }
    if (packages.keys.any(requiredPackages.containsKey)) {
      return ConfigBinding.invalid(
        'required semantic packages cannot become approved visual packages',
      );
    }

    final rawIdentities = decoded['approvedIdentities'];
    if (rawIdentities is! Map<String, dynamic> ||
        !_hasExactKeys(rawIdentities, _identityCategories)) {
      return ConfigBinding.invalid('approvedIdentities must contain every exact category');
    }
    final identities = <String, Set<String>>{};
    for (final category in _identityCategories) {
      final values = _parseIdentityList(rawIdentities[category], allowEmpty: true);
      if (values == null) {
        return ConfigBinding.invalid('$category contains a malformed or duplicate identity');
      }
      identities[category] = values;
    }
    final usedPackages = <String>{};
    for (final entry in identities.entries) {
      for (final identity in entry.value) {
        final packageName = _packageNameFromIdentity(identity);
        if (packageName == null || !packages.containsKey(packageName)) {
          return ConfigBinding.invalid(
            'approved identity lacks exact approved package provenance',
          );
        }
        usedPackages.add(packageName);
      }
    }

    final rawVariants = decoded['componentVariants'];
    if (rawVariants is! Map<String, dynamic>) {
      return ConfigBinding.invalid('componentVariants must be an object');
    }
    final variants = <String, Map<String, Set<String>>>{};
    for (final entry in rawVariants.entries) {
      if (!_isCodeIdentity(entry.key) || !identities['widgets']!.contains(entry.key)) {
        return ConfigBinding.invalid(
          'componentVariants key must be an approved widget identity: ${entry.key}',
        );
      }
      if (entry.value is! Map<String, dynamic> ||
          (entry.value as Map<String, dynamic>).isEmpty) {
        return ConfigBinding.invalid('component variant properties must be a non-empty object');
      }
      final widgetPackage = _packageNameFromIdentity(entry.key);
      if (widgetPackage == null || !packages.containsKey(widgetPackage)) {
        return ConfigBinding.invalid(
          'component variant widget lacks exact approved package provenance',
        );
      }
      usedPackages.add(widgetPackage);
      final propertyMap = <String, Set<String>>{};
      for (final property in (entry.value as Map<String, dynamic>).entries) {
        if (property.key.isEmpty) {
          return ConfigBinding.invalid('component variant property name cannot be empty');
        }
        final values = _parseIdentityList(property.value, allowEmpty: false);
        if (values == null) {
          return ConfigBinding.invalid(
            'variant ${entry.key}.${property.key} must contain exact identities',
          );
        }
        if (values.any(
          (identity) => _packageNameFromIdentity(identity) != widgetPackage,
        )) {
          return ConfigBinding.invalid(
            'component variant identity impersonates a different package',
          );
        }
        propertyMap[property.key] = values;
      }
      variants[entry.key] = propertyMap;
    }

    if (usedPackages.length != packages.length ||
        !usedPackages.containsAll(packages.keys)) {
      return ConfigBinding.invalid(
        'approvedPackages must exactly bind all approved identities',
      );
    }
    return ConfigBinding.valid(
      GuardianAdapterConfig(
        profileId: profileId,
        policyDigest: policyDigest,
        snapshotId: snapshotId,
        sourceCutDigest: sourceCutDigest,
        configDigest: configDigest,
        toolchain: toolchain,
        requiredPackages: requiredPackages,
        approvedPackages: packages,
        approvedIdentities: identities,
        componentVariants: variants,
      ),
    );
  }
}

bool verifyConfigDigest(Map<String, dynamic> document) {
  final claimed = document['configDigest'];
  if (claimed is! String || !_isDigest(claimed)) return false;
  final unsigned = Map<String, dynamic>.from(document)..remove('configDigest');
  final encoded = utf8.encode(_canonicalJson(unsigned));
  return sha256.convert(encoded).toString() == claimed;
}

String _canonicalJson(Object? value) {
  Object? normalize(Object? current) {
    if (current is Map) {
      final keys = current.keys.map((key) => key.toString()).toList()..sort();
      return <String, Object?>{
        for (final key in keys) key: normalize(current[key]),
      };
    }
    if (current is List) return current.map(normalize).toList(growable: false);
    return current;
  }

  return jsonEncode(normalize(value));
}

bool _hasExactKeys(Map<String, dynamic> value, Set<String> expected) =>
    value.keys.toSet().length == expected.length && value.keys.toSet().containsAll(expected);

bool _isDigest(String value) =>
    value.length == 64 && value.codeUnits.every(_isLowerHexCodeUnit);

bool _isLowerHexCodeUnit(int codeUnit) =>
    (codeUnit >= 48 && codeUnit <= 57) || (codeUnit >= 97 && codeUnit <= 102);

bool _isRepositoryCommit(String value) =>
    (value.length == 40 || value.length == 64) &&
    value.codeUnits.every(_isLowerHexCodeUnit);

bool _isPackageName(String value) {
  if (value.isEmpty || value.codeUnitAt(0) < 97 || value.codeUnitAt(0) > 122) {
    return false;
  }
  return value.codeUnits.every(
    (codeUnit) =>
        (codeUnit >= 97 && codeUnit <= 122) ||
        (codeUnit >= 48 && codeUnit <= 57) ||
        codeUnit == 95,
  );
}

String? _packageNameFromIdentity(String value) {
  if (!value.startsWith('package:') ||
      value.startsWith('package:flutter/') ||
      value.startsWith('package:design_system_guardian_flutter/')) {
    return null;
  }
  final hash = value.indexOf('#');
  if (hash <= 'package:'.length || hash == value.length - 1) return null;
  final uri = value.substring('package:'.length, hash);
  if (uri.contains('\\') ||
      uri.contains('%') ||
      uri.contains('?') ||
      uri.contains(':')) {
    return null;
  }
  final parts = uri.split('/');
  if (parts.length < 2 ||
      !_isPackageName(parts.first) ||
      parts.any((part) => part.isEmpty || part == '.' || part == '..')) {
    return null;
  }
  return parts.first;
}

bool _isCodeIdentity(String value) {
  final hash = value.indexOf('#');
  if (hash <= 0 || hash == value.length - 1) return false;
  final uri = value.substring(0, hash);
  return (uri.startsWith('package:') || uri.startsWith('dart:')) && !value.contains(' ');
}

Set<String>? _parseIdentityList(Object? value, {required bool allowEmpty}) {
  if (value is! List || (!allowEmpty && value.isEmpty)) return null;
  final output = <String>{};
  for (final item in value) {
    if (item is! String || !_isCodeIdentity(item) || !output.add(item)) return null;
  }
  final sorted = output.toList()..sort();
  if (value.length != sorted.length) return null;
  for (var index = 0; index < sorted.length; index++) {
    if (value[index] != sorted[index]) return null;
  }
  return Set<String>.unmodifiable(output);
}
