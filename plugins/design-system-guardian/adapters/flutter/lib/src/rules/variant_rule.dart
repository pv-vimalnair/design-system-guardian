import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/canonical_element_identity.dart';
import 'rule_support.dart';

final class GuardianVariantRule extends AnalysisRule {
  GuardianVariantRule()
    : super(
        name: code.name,
        description:
            'Requires explicit, exact approved identities for governed componentVariants.',
      );

  static const LintCode code = LintCode(
    'guardian_unapproved_component_variant',
    'Component variant property "{0}" is missing or not an exact approved identity.',
    correctionMessage:
        'Select an explicitly approved variant from the pinned adapter config.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    final visitor = _VariantVisitor(this, context);
    registry.addInstanceCreationExpression(this, visitor);
    registry.addMethodInvocation(this, visitor);
    registry.addFunctionExpressionInvocation(this, visitor);
  }
}

final class _VariantVisitor extends SimpleAstVisitor<void> {
  _VariantVisitor(this.rule, this.context);

  final GuardianVariantRule rule;
  final RuleContext context;

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _checkInvocation(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) => _checkInvocation(node);

  @override
  void visitFunctionExpressionInvocation(FunctionExpressionInvocation node) =>
      _checkInvocation(node);

  void _checkInvocation(Expression invocation) {
    final config = validConfig(context);
    if (config == null) return;
    final componentIdentity = canonicalExpressionIdentity(invocation);
    if (!config.isApproved('widgets', componentIdentity)) return;
    final governedProperties = config.variantsFor(componentIdentity);
    if (governedProperties == null) return;

    final supplied = <String, Expression>{};
    for (final argument in governedArguments(invocation)) {
      final name = argument.parameterName;
      if (name != null) supplied[name] = argument.expression;
    }
    for (final entry in governedProperties.entries) {
      final expression = supplied[entry.key];
      final identity = expression == null
          ? null
          : canonicalExpressionIdentity(expression);
      final frameworkDefault = isFrameworkDefaultIdentity(identity);
      if (frameworkDefault ||
          identity == null ||
          !entry.value.contains(identity)) {
        rule.reportAtNode(invocation, arguments: <Object>[entry.key]);
      }
    }
  }
}
