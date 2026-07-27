import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/adapter_config.dart';

/// Emits exactly one host-verifiable proof marker for every resolved unit.
///
/// The host runner removes this marker only after matching every hashed source
/// path and the exact pinned config digest. It is deliberately a default-on
/// warning so an empty diagnostic stream can never impersonate plugin success.
final class GuardianCompilationUnitAttestationRule extends AnalysisRule {
  GuardianCompilationUnitAttestationRule()
    : super(
        name: code.lowerCaseName,
        description:
            'Attests that Guardian analyzed this compilation unit with the pinned config.',
      );

  static const LintCode code = LintCode(
    'guardian_compilation_unit_attestation',
    'DSG_ATTESTATION_V1 configDigest={0}',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    registry.addCompilationUnit(this, _AttestationVisitor(this, context));
  }
}

final class _AttestationVisitor extends SimpleAstVisitor<void> {
  _AttestationVisitor(this.rule, this.context);

  final GuardianCompilationUnitAttestationRule rule;
  final RuleContext context;

  @override
  void visitCompilationUnit(CompilationUnit node) {
    final binding = GuardianAdapterConfigRepository.load(context);
    if (!binding.isValid) return;
    rule.reportAtToken(
      node.beginToken,
      arguments: <Object>[binding.config!.configDigest],
    );
  }
}
