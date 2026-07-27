import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';
import 'package:analyzer_testing/analysis_rule/analysis_rule.dart';
import 'package:design_system_guardian_flutter/src/config/adapter_config.dart';
import 'package:design_system_guardian_flutter/src/rules/usage_rule.dart';
import 'package:test/test.dart';
import 'package:test_reflective_loader/test_reflective_loader.dart';

void main() {
  defineReflectiveSuite(() {
    defineReflectiveTests(UsageRuleInvocationFormsTest);
  });

  const approved = 'package:company_design/design.dart#ApprovedCard';
  const similar = 'package:company_design/design.dart#ApprovedCardCopy';

  test('forbidden identity reports the first exact occurrence only', () {
    const rule = GuardianCompiledUsageRule(
      ruleId: 'card.forbidden',
      predicate: 'forbidden_identity_in_scope',
      constructorIdentities: <String>{approved},
      maximum: 0,
    );
    expect(
      firstUsageRuleViolationIndex(rule, <String>[similar, approved, approved]),
      1,
    );
    expect(firstUsageRuleViolationIndex(rule, <String>[similar]), isNull);
  });

  test('maximum reports the first exact occurrence above the boundary', () {
    const rule = GuardianCompiledUsageRule(
      ruleId: 'card.maximum',
      predicate: 'max_instances_per_scope',
      constructorIdentities: <String>{approved},
      maximum: 2,
    );
    expect(
      firstUsageRuleViolationIndex(rule, <String>[
        approved,
        similar,
        approved,
        approved,
      ]),
      3,
    );
    expect(
      firstUsageRuleViolationIndex(rule, <String>[approved, approved]),
      isNull,
    );
  });
}

final class _UsageRuleInvocationProbe extends AnalysisRule {
  _UsageRuleInvocationProbe()
    : super(
        name: code.lowerCaseName,
        description:
            'Exercises exact usage-rule invocation identity resolution.',
      );

  static const LintCode code = LintCode(
    'guardian_test_usage_rule_invocation',
    'Resolved invocation participates in Guardian usage-rule counting.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    final visitor = _UsageRuleInvocationProbeVisitor(this);
    registry.addInstanceCreationExpression(this, visitor);
    registry.addMethodInvocation(this, visitor);
    registry.addFunctionExpressionInvocation(this, visitor);
  }
}

final class _UsageRuleInvocationProbeVisitor extends SimpleAstVisitor<void> {
  _UsageRuleInvocationProbeVisitor(this.rule);

  final _UsageRuleInvocationProbe rule;

  void _check(Expression node) {
    if (usageRuleInvocationIdentity(node) != null) {
      rule.reportAtNode(node);
    }
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) =>
      _check(node);

  @override
  void visitMethodInvocation(MethodInvocation node) => _check(node);

  @override
  void visitFunctionExpressionInvocation(FunctionExpressionInvocation node) =>
      _check(node);
}

@reflectiveTest
final class UsageRuleInvocationFormsTest extends AnalysisRuleTest {
  @override
  void setUp() {
    rule = _UsageRuleInvocationProbe();
    super.setUp();
  }

  Future<void> test_exactResolvedInvocationForms_areAllCountable() async {
    const source = r'''
class ApprovedCard {
  factory ApprovedCard() => throw 0;
  static ApprovedCard make() => throw 0;
}

void use() {
  ApprovedCard();
  ApprovedCard.make();
  (ApprovedCard.make)();
}
''';
    const constructor = 'ApprovedCard()';
    const method = 'ApprovedCard.make()';
    const functionExpression = '(ApprovedCard.make)()';
    await assertDiagnostics(source, [
      lint(source.indexOf('$constructor;'), constructor.length),
      lint(source.indexOf('$method;'), method.length),
      lint(source.indexOf('$functionExpression;'), functionExpression.length),
    ]);
  }
}
