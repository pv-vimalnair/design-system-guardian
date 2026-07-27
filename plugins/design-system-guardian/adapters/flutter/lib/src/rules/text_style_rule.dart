import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/canonical_element_identity.dart';
import 'rule_support.dart';

final class GuardianTextStyleRule extends AnalysisRule {
  GuardianTextStyleRule()
    : super(
        name: code.lowerCaseName,
        description:
            'Rejects raw or unapproved TextStyle construction and references.',
      );

  static const LintCode code = LintCode(
    'guardian_unapproved_text_style',
    'Text presentation must resolve to an exact approved text-style identity.',
    correctionMessage:
        'Use an approved typography token or a Guardian MISSING TEXT STYLE sentinel.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    final visitor = _TextStyleVisitor(this, context);
    registry.addInstanceCreationExpression(this, visitor);
    registry.addMethodInvocation(this, visitor);
    registry.addFunctionExpressionInvocation(this, visitor);
    registry.addIndexExpression(this, visitor);
    registry.addPrefixedIdentifier(this, visitor);
    registry.addPropertyAccess(this, visitor);
    registry.addSimpleIdentifier(this, visitor);
  }
}

final class _TextStyleVisitor extends SimpleAstVisitor<void> {
  _TextStyleVisitor(this.rule, this.context);

  final GuardianTextStyleRule rule;
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
    if (!expressionHasGovernedType(node, 'textStyles')) return;
    final config = validConfig(context);
    if (config == null) return;
    final identity = canonicalExpressionIdentity(node);
    final frameworkDefault = isFrameworkDefaultIdentity(identity);
    if (frameworkDefault || !config.isApproved('textStyles', identity)) {
      rule.reportAtNode(node);
    }
  }
}
