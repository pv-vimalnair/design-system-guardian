import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/adapter_config.dart';

final class GuardianConfigBindingRule extends AnalysisRule {
  GuardianConfigBindingRule()
    : super(
        name: code.lowerCaseName,
        description:
            'Requires a complete, digest-verified adapter config bound to a pinned Guardian run.',
      );

  static const LintCode code = LintCode(
    'guardian_invalid_config_binding',
    'Design System Guardian cannot assess this file: {0}.',
    correctionMessage:
        'Generate a fresh Flutter adapter config from the pinned Guardian snapshot.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    registry.addCompilationUnit(this, _ConfigBindingVisitor(this, context));
  }
}

final class _ConfigBindingVisitor extends SimpleAstVisitor<void> {
  _ConfigBindingVisitor(this.rule, this.context);

  final GuardianConfigBindingRule rule;
  final RuleContext context;

  @override
  void visitCompilationUnit(CompilationUnit node) {
    final binding = GuardianAdapterConfigRepository.load(context);
    if (!binding.isValid) {
      rule.reportAtToken(
        node.beginToken,
        arguments: <Object>[binding.reason ?? 'unbound config'],
      );
    }
  }
}
