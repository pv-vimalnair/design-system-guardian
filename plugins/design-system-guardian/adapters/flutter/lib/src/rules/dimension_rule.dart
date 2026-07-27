import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/canonical_element_identity.dart';
import 'rule_support.dart';

final class GuardianDimensionRule extends AnalysisRule {
  GuardianDimensionRule()
    : super(
        name: code.lowerCaseName,
        description:
            'Rejects raw or unapproved spacing, sizing, radius, and elevation values.',
      );

  static const LintCode code = LintCode(
    'guardian_unapproved_dimension',
    'Visual dimension must resolve to an exact approved design-system token.',
    correctionMessage:
        'Use an approved spacing, size, radius, or elevation identity.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    final visitor = _DimensionVisitor(this, context);
    registry.addNamedArgument(this, visitor);
    registry.addInstanceCreationExpression(this, visitor);
    registry.addMethodInvocation(this, visitor);
    registry.addFunctionExpressionInvocation(this, visitor);
  }
}

final class _DimensionVisitor extends SimpleAstVisitor<void> {
  _DimensionVisitor(this.rule, this.context);

  final GuardianDimensionRule rule;
  final RuleContext context;

  @override
  void visitNamedArgument(NamedArgument node) {
    final property = node.name.lexeme;
    if (!visualDimensionArguments.contains(property)) return;
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
          visualDimensionArguments.contains(argument.parameterName);
      final governedByPosition =
          positionalDimensionArguments[argument.calleeIdentity]?.contains(
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
    final rawLiteral =
        expression is IntegerLiteral || expression is DoubleLiteral;
    final identity = canonicalExpressionIdentity(expression);
    final frameworkDefault = isFrameworkDefaultIdentity(identity);
    if (rawLiteral ||
        frameworkDefault ||
        !config.isApproved('dimensions', identity)) {
      rule.reportAtNode(expression);
    }
  }
}
