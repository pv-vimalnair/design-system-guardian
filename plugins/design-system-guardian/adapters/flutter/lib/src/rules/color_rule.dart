import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/canonical_element_identity.dart';
import 'rule_support.dart';

final class GuardianColorRule extends AnalysisRule {
  GuardianColorRule()
    : super(
        name: code.name,
        description:
            'Rejects raw, framework-default, or unapproved color identities.',
      );

  static const LintCode code = LintCode(
    'guardian_unapproved_color',
    'Color must resolve to an exact approved design-system identity.',
    correctionMessage:
        'Use an approved color token or a Guardian MISSING COLOR sentinel.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    final visitor = _ColorVisitor(this, context);
    registry.addInstanceCreationExpression(this, visitor);
    registry.addMethodInvocation(this, visitor);
    registry.addFunctionExpressionInvocation(this, visitor);
    registry.addIndexExpression(this, visitor);
    registry.addPrefixedIdentifier(this, visitor);
    registry.addPropertyAccess(this, visitor);
    registry.addSimpleIdentifier(this, visitor);
  }
}

final class _ColorVisitor extends SimpleAstVisitor<void> {
  _ColorVisitor(this.rule, this.context);

  final GuardianColorRule rule;
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
    if (!expressionHasGovernedType(node, 'colors')) return;
    final config = validConfig(context);
    if (config == null) return;
    final identity = canonicalExpressionIdentity(node);
    final frameworkDefault = isFrameworkDefaultIdentity(identity);
    if (frameworkDefault || !config.isApproved('colors', identity)) {
      rule.reportAtNode(node);
    }
  }
}
