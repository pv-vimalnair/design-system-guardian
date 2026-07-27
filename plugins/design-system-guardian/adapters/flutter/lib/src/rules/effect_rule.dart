import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/canonical_element_identity.dart';
import 'rule_support.dart';

final class GuardianEffectRule extends AnalysisRule {
  GuardianEffectRule()
    : super(
        name: code.lowerCaseName,
        description:
            'Rejects raw or unapproved shadows, blurs, gradients, and visual effects.',
      );

  static const LintCode code = LintCode(
    'guardian_unapproved_effect',
    'Visual effect must resolve to an exact approved design-system identity.',
    correctionMessage:
        'Use an approved effect token; do not recreate or approximate it.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    final visitor = _EffectVisitor(this, context);
    registry.addInstanceCreationExpression(this, visitor);
    registry.addMethodInvocation(this, visitor);
    registry.addFunctionExpressionInvocation(this, visitor);
    registry.addIndexExpression(this, visitor);
    registry.addPrefixedIdentifier(this, visitor);
    registry.addPropertyAccess(this, visitor);
    registry.addSimpleIdentifier(this, visitor);
  }
}

final class _EffectVisitor extends SimpleAstVisitor<void> {
  _EffectVisitor(this.rule, this.context);

  final GuardianEffectRule rule;
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
    if (!expressionHasGovernedType(node, 'effects')) return;
    final config = validConfig(context);
    if (config == null) return;
    final identity = canonicalExpressionIdentity(node);
    final frameworkDefault = isFrameworkDefaultIdentity(identity);
    if (frameworkDefault || !config.isApproved('effects', identity)) {
      rule.reportAtNode(node);
    }
  }
}
