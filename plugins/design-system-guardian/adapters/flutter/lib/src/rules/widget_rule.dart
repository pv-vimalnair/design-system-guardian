import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/canonical_element_identity.dart';
import 'rule_support.dart';

final class GuardianWidgetRule extends AnalysisRule {
  GuardianWidgetRule()
    : super(
        name: code.name,
        description:
            'Rejects widgets and components without an exact approved constructor mapping.',
      );

  static const LintCode code = LintCode(
    'guardian_unapproved_widget',
    'Widget must resolve to an exact approved design-system component identity.',
    correctionMessage:
        'Compose approved primitives or use a Guardian MISSING COMPONENT sentinel.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    final visitor = _WidgetVisitor(this, context);
    registry.addInstanceCreationExpression(this, visitor);
    registry.addMethodInvocation(this, visitor);
    registry.addFunctionExpressionInvocation(this, visitor);
    registry.addIndexExpression(this, visitor);
    registry.addPrefixedIdentifier(this, visitor);
    registry.addPropertyAccess(this, visitor);
    registry.addSimpleIdentifier(this, visitor);
  }
}

final class _WidgetVisitor extends SimpleAstVisitor<void> {
  _WidgetVisitor(this.rule, this.context);

  final GuardianWidgetRule rule;
  final RuleContext context;

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _check(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) => _check(node);

  @override
  void visitFunctionExpressionInvocation(FunctionExpressionInvocation node) =>
      _check(node);

  @override
  void visitIndexExpression(IndexExpression node) => _check(node);

  @override
  void visitPrefixedIdentifier(PrefixedIdentifier node) => _check(node);

  @override
  void visitPropertyAccess(PropertyAccess node) => _check(node);

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    if (node.parent is PrefixedIdentifier || node.parent is PropertyAccess)
      return;
    _check(node);
  }

  void _check(Expression node) {
    if (!expressionHasGovernedType(node, 'widgets')) return;
    final identity = canonicalExpressionIdentity(node);
    if (isGuardianSentinelIdentity(identity)) return;
    final config = validConfig(context);
    if (config == null) return;
    final frameworkDefault = isFrameworkDefaultIdentity(identity);
    if (frameworkDefault || !config.isApproved('widgets', identity)) {
      rule.reportAtNode(node);
    }
  }
}
