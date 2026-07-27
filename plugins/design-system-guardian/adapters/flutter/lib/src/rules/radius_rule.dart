import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/canonical_element_identity.dart';
import 'rule_support.dart';

final class GuardianRadiusRule extends AnalysisRule {
  GuardianRadiusRule()
    : super(
        name: code.lowerCaseName,
        description: 'Rejects raw or unapproved corner-radius values.',
      );

  static const LintCode code = LintCode(
    'guardian_unapproved_radius',
    'Radius must resolve to an exact approved design-system dimension token.',
    correctionMessage:
        'Use an approved radius identity; do not round or approximate it.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    final visitor = _RadiusVisitor(this, context);
    registry.addNamedArgument(this, visitor);
    registry.addInstanceCreationExpression(this, visitor);
    registry.addMethodInvocation(this, visitor);
    registry.addFunctionExpressionInvocation(this, visitor);
  }
}

final class _RadiusVisitor extends SimpleAstVisitor<void> {
  _RadiusVisitor(this.rule, this.context);

  final GuardianRadiusRule rule;
  final RuleContext context;

  @override
  void visitNamedArgument(NamedArgument node) {
    if (!radiusArguments.contains(node.name.lexeme)) return;
    _check(node.argumentExpression);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) =>
      _checkInvocation(node);

  @override
  void visitMethodInvocation(MethodInvocation node) => _checkInvocation(node);

  @override
  void visitFunctionExpressionInvocation(FunctionExpressionInvocation node) =>
      _checkInvocation(node);

  void _checkInvocation(Expression invocation) {
    for (final argument in governedArguments(invocation)) {
      if (argument.named) continue;
      final governedByName =
          argument.parameterName != null &&
          radiusArguments.contains(argument.parameterName);
      final governedByPosition =
          positionalRadiusArguments[argument.calleeIdentity]?.contains(
            argument.index,
          ) ??
          false;
      if (governedByName || governedByPosition) _check(argument.expression);
    }
  }

  void _check(Expression raw) {
    final config = validConfig(context);
    if (config == null) return;
    final expression = raw.unParenthesized;
    final identity = canonicalExpressionIdentity(expression);
    final rawLiteral =
        expression is IntegerLiteral || expression is DoubleLiteral;
    final frameworkDefault = isFrameworkDefaultIdentity(identity);
    if (rawLiteral ||
        frameworkDefault ||
        !config.isApproved('dimensions', identity)) {
      rule.reportAtNode(expression);
    }
  }
}
