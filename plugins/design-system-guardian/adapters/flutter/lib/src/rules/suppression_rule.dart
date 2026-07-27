import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/token.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import 'rule_support.dart';

final class GuardianSuppressionRule extends AnalysisRule {
  GuardianSuppressionRule()
    : super(
        name: code.name,
        description:
            'Rejects attempts to suppress or bypass Guardian diagnostics.',
      );

  static const LintCode code = LintCode(
    'guardian_suppression_forbidden',
    'Design System Guardian diagnostics cannot be suppressed.',
    correctionMessage:
        'Remove the suppression and resolve the design-system violation.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    registry.addCompilationUnit(this, _SuppressionVisitor(this, context));
  }
}

final class _SuppressionVisitor extends SimpleAstVisitor<void> {
  _SuppressionVisitor(this.rule, this.context);

  final GuardianSuppressionRule rule;
  final RuleContext context;

  @override
  void visitCompilationUnit(CompilationUnit node) {
    // Loading the config keeps suppression diagnostics fail-closed with the
    // same bound catalog as all other rules. The suppression itself is denied
    // even when config is invalid.
    validConfig(context);
    final reportedOffsets = <int>{};
    Token token = node.beginToken;
    while (true) {
      Token? comment = token.precedingComments;
      while (comment != null) {
        if (_isGuardianSuppression(comment.lexeme) &&
            reportedOffsets.add(comment.offset)) {
          rule.reportAtToken(comment);
        }
        comment = comment.next;
      }
      if (identical(token, node.endToken) || token.next == null) break;
      token = token.next!;
    }
  }

  bool _isGuardianSuppression(String source) {
    final normalized = source.toLowerCase();
    final hasIgnoreDirective =
        normalized.contains('ignore:') ||
        normalized.contains('ignore_for_file:') ||
        normalized.contains('ignore_for_file=');
    final targetsGuardian =
        normalized.contains('design_system_guardian_flutter/') ||
        normalized.contains('guardian_');
    final bypassMarker =
        normalized.contains('guardian: ignore') ||
        normalized.contains('guardian-ignore') ||
        normalized.contains('guardian_bypass');
    return (hasIgnoreDirective && targetsGuardian) || bypassMarker;
  }
}
