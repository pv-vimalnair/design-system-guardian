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
import 'usage_rule_evaluator.dart';

export 'usage_rule_evaluator.dart';

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

/// Preserves config-v2 enforcement exactly and evaluates config-v3 machine
/// predicates only from analyzer-resolved construction evidence.
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
    if (config == null || config.activeUsageRules.isEmpty) return;
    if (config.schemaVersion == 2) {
      _evaluateLegacy(node, config);
      return;
    }
    if (config.schemaVersion != 3) return;

    final evidence = buildGuardianUsageUnitEvidence(
      node,
      approvedMappedConstructorIdentities:
          config.approvedIdentities['widgets']!,
    );
    for (final usageRule in config.activeUsageRules) {
      final evaluation = evaluateGuardianUsageRule(usageRule, evidence);
      for (final index in evaluation.violationIndices) {
        final invocation = evidence.invocations[index];
        final invocationNode = invocation.node;
        if (invocationNode == null) continue;
        rule.reportAtNode(
          invocationNode,
          arguments: <Object>[usageRule.ruleId],
        );
      }
    }
  }

  void _evaluateLegacy(CompilationUnit node, GuardianAdapterConfig config) {
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

/// Emits one machine-readable marker for every active config-v3 rule that
/// cannot be fully assessed from the current resolved compilation unit.
final class GuardianUsageRuleCoverageRule extends AnalysisRule {
  GuardianUsageRuleCoverageRule()
    : super(
        name: code.name,
        description:
            'Reports explicit incomplete machine-rule construction evidence.',
      );

  static const LintCode code = LintCode(
    'guardian_usage_rule_not_assessed',
    'DSG_USAGE_RULE_NOT_ASSESSED_V1 ruleId={0} reasonCode={1}',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    registry.addCompilationUnit(
      this,
      _UsageRuleCoverageUnitVisitor(this, context),
    );
  }
}

final class _UsageRuleCoverageUnitVisitor extends SimpleAstVisitor<void> {
  _UsageRuleCoverageUnitVisitor(this.rule, this.context);

  final GuardianUsageRuleCoverageRule rule;
  final RuleContext context;

  @override
  void visitCompilationUnit(CompilationUnit node) {
    final config = validConfig(context);
    if (config == null ||
        config.schemaVersion != 3 ||
        config.activeUsageRules.isEmpty) {
      return;
    }
    final evidence = buildGuardianUsageUnitEvidence(
      node,
      approvedMappedConstructorIdentities:
          config.approvedIdentities['widgets']!,
    );
    for (final usageRule in config.activeUsageRules) {
      final evaluation = evaluateGuardianUsageRule(usageRule, evidence);
      if (evaluation.status != GuardianUsageEvaluationStatus.notAssessed) {
        continue;
      }
      final index = evaluation.notAssessedIndex;
      final invocationNode = index == null
          ? null
          : evidence.invocations[index].node;
      final arguments = <Object>[usageRule.ruleId, evaluation.reasonCode!];
      if (invocationNode != null) {
        rule.reportAtNode(invocationNode, arguments: arguments);
      } else {
        rule.reportAtToken(node.beginToken, arguments: arguments);
      }
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
