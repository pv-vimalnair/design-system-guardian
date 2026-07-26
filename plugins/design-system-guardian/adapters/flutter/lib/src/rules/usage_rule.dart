import 'dart:collection';

import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/adapter_config.dart';
import '../config/canonical_element_identity.dart';
import 'rule_support.dart';

/// Returns only the analyzer-resolved identity forms already governed by the
/// widget rule. Source spelling and wrapper guesses never enter usage counts.
String? usageRuleInvocationIdentity(Expression node) =>
    canonicalExpressionIdentity(node);

int? firstUsageRuleViolationIndex(
  GuardianCompiledUsageRule rule,
  Iterable<String> constructorIdentities,
) {
  var matchingCount = 0;
  var sourceIndex = 0;
  for (final identity in constructorIdentities) {
    if (rule.constructorIdentities.contains(identity)) {
      if (matchingCount == rule.maximum) return sourceIndex;
      matchingCount++;
    }
    sourceIndex++;
  }
  return null;
}

/// Enforces only the exact usage-rule capabilities activated by config v2.
///
/// The host compiler leaves every unsupported, judgment-based, or unmapped
/// rule out of [GuardianAdapterConfig.activeUsageRules] and marks coverage
/// incomplete. This analyzer rule therefore never guesses an invocation.
final class GuardianUsageRule extends AnalysisRule {
  GuardianUsageRule()
      : super(
          name: code.name,
          description:
              'Enforces exact approved design-system usage rules per compilation unit.',
        );

  static const LintCode code = LintCode(
    'guardian_usage_rule',
    'Design-system usage rule {0} is violated in this compilation unit.',
    correctionMessage:
        'Use only the exact approved component composition allowed by the rule snapshot.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    registry.addCompilationUnit(this, _UsageRuleUnitVisitor(this, context));
  }
}

final class _UsageRuleUnitVisitor extends SimpleAstVisitor<void> {
  _UsageRuleUnitVisitor(this.rule, this.context);

  final GuardianUsageRule rule;
  final RuleContext context;

  @override
  void visitCompilationUnit(CompilationUnit node) {
    final config = validConfig(context);
    if (config == null ||
        config.schemaVersion != 2 ||
        config.activeUsageRules.isEmpty) {
      return;
    }
    final collector = _ResolvedInvocationCollector();
    node.accept(collector);
    collector.sortInSourceOrder();
    for (final usageRule in config.activeUsageRules) {
      final violationIndex = firstUsageRuleViolationIndex(
        usageRule,
        collector.invocations.map((item) => item.identity),
      );
      if (violationIndex == null) continue;
      rule.reportAtNode(
        collector.invocations[violationIndex].node,
        arguments: <Object>[usageRule.ruleId],
      );
    }
  }
}

final class _ResolvedInvocationCollector extends RecursiveAstVisitor<void> {
  final List<({String identity, Expression node})> invocations =
      <({String identity, Expression node})>[];
  final Set<Expression> _seenNodes = HashSet<Expression>.identity();

  void _record(Expression node) {
    if (!_seenNodes.add(node)) return;
    final identity = usageRuleInvocationIdentity(node);
    if (identity != null) {
      invocations.add((identity: identity, node: node));
    }
  }

  void sortInSourceOrder() {
    invocations.sort((left, right) {
      final offset = left.node.offset.compareTo(right.node.offset);
      if (offset != 0) return offset;
      final length = left.node.length.compareTo(right.node.length);
      if (length != 0) return length;
      return left.identity.compareTo(right.identity);
    });
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _record(node);
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    _record(node);
    super.visitMethodInvocation(node);
  }

  @override
  void visitFunctionExpressionInvocation(FunctionExpressionInvocation node) {
    _record(node);
    super.visitFunctionExpressionInvocation(node);
  }
}
