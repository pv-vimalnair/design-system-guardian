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
    defineReflectiveTests(UsageRuleResolvedOwnershipTest);
  });

  const outer = 'package:design/kit.dart#Outer';
  const inner = 'package:design/kit.dart#Inner';
  const companion = 'package:design/kit.dart#Companion';
  const table = 'package:design/kit.dart#Table';
  const variant = 'package:design/kit.dart#ButtonVariant.compact';

  GuardianUsageInvocation invocation(
    String identity,
    int offset, {
    int? parentIndex,
    bool parentResolved = true,
    GuardianUsageOwnership ownership = GuardianUsageOwnership.outside,
    String? ownerScopeId,
    bool subtreeComplete = true,
    Map<String, String?> namedArgumentIdentities = const <String, String?>{},
  }) => GuardianUsageInvocation(
    identity: identity,
    sourceOffset: offset,
    sourceLength: 1,
    parentIndex: parentIndex,
    parentResolved: parentResolved,
    ownership: ownership,
    ownerScopeId: ownerScopeId,
    subtreeComplete: subtreeComplete,
    namedArgumentIdentities: namedArgumentIdentities,
  );

  test('both scopes remain separate and unresolved ownership never passes', () {
    const rule = GuardianCompiledUsageRule(
      ruleId: 'card.maximum',
      predicate: 'max_instances_per_scope',
      scope: 'widget_class',
      constructorIdentities: <String>{inner},
      maximum: 1,
    );
    final separate = GuardianUsageUnitEvidence(
      complete: true,
      invocations: <GuardianUsageInvocation>[
        invocation(
          inner,
          1,
          ownership: GuardianUsageOwnership.widgetClass,
          ownerScopeId: 'class:1',
        ),
        invocation(
          inner,
          2,
          ownership: GuardianUsageOwnership.widgetClass,
          ownerScopeId: 'class:2',
        ),
      ],
    );
    expect(
      evaluateGuardianUsageRule(rule, separate).status,
      GuardianUsageEvaluationStatus.allowed,
    );

    final unresolved = GuardianUsageUnitEvidence(
      complete: true,
      invocations: <GuardianUsageInvocation>[
        invocation(inner, 1, ownership: GuardianUsageOwnership.unresolved),
      ],
    );
    final result = evaluateGuardianUsageRule(rule, unresolved);
    expect(result.status, GuardianUsageEvaluationStatus.notAssessed);
    expect(result.reasonCode, 'incomplete_construction_graph');
  });

  test('forbidden scope and maximum use exact identities only', () {
    const similar = 'package:design/kit.dart#InnerCopy';
    const forbidden = GuardianCompiledUsageRule(
      ruleId: 'inner.forbidden',
      predicate: 'forbidden_identity_in_scope',
      scope: 'compilation_unit',
      constructorIdentities: <String>{inner},
      maximum: 0,
    );
    const maximum = GuardianCompiledUsageRule(
      ruleId: 'inner.maximum',
      predicate: 'max_instances_per_scope',
      scope: 'compilation_unit',
      constructorIdentities: <String>{inner},
      maximum: 1,
    );
    final evidence = GuardianUsageUnitEvidence(
      complete: true,
      invocations: <GuardianUsageInvocation>[
        invocation(similar, 1),
        invocation(inner, 2),
        invocation(inner, 3),
      ],
    );
    expect(
      evaluateGuardianUsageRule(forbidden, evidence).violationIndices,
      <int>[1, 2],
    );
    expect(evaluateGuardianUsageRule(maximum, evidence).violationIndices, <int>[
      2,
    ]);
  });

  test('nesting uses proven transitive construction ancestry', () {
    const rule = GuardianCompiledUsageRule(
      ruleId: 'nesting.forbidden',
      predicate: 'forbidden_nesting',
      outerConstructorIdentities: <String>{outer},
      innerConstructorIdentities: <String>{inner},
    );
    final violation = GuardianUsageUnitEvidence(
      complete: true,
      invocations: <GuardianUsageInvocation>[
        invocation(outer, 1),
        invocation(table, 2, parentIndex: 0),
        invocation(inner, 3, parentIndex: 1),
      ],
    );
    expect(evaluateGuardianUsageRule(rule, violation).violationIndices, <int>[
      2,
    ]);

    final incomplete = GuardianUsageUnitEvidence(
      complete: true,
      invocations: <GuardianUsageInvocation>[
        invocation(outer, 1, subtreeComplete: false),
      ],
    );
    final result = evaluateGuardianUsageRule(rule, incomplete);
    expect(result.status, GuardianUsageEvaluationStatus.notAssessed);
    expect(result.reasonCode, 'incomplete_construction_graph');
  });

  test('required companion supports child descendant and sibling exactly', () {
    final evidence = GuardianUsageUnitEvidence(
      complete: true,
      invocations: <GuardianUsageInvocation>[
        invocation(outer, 1),
        invocation(inner, 2, parentIndex: 0),
        invocation(table, 3, parentIndex: 1),
        invocation(companion, 4, parentIndex: 1),
      ],
    );
    for (final relation in <String>['child', 'descendant', 'sibling']) {
      final rule = GuardianCompiledUsageRule(
        ruleId: 'companion.$relation',
        predicate: 'required_companion',
        constructorIdentities: const <String>{inner},
        companionConstructorIdentities: const <String>{companion},
        relation: relation,
      );
      final result = evaluateGuardianUsageRule(rule, evidence);
      if (relation == 'child' || relation == 'descendant') {
        expect(result.status, GuardianUsageEvaluationStatus.allowed);
      } else {
        expect(result.status, GuardianUsageEvaluationStatus.conflict);
      }
    }

    const siblingRule = GuardianCompiledUsageRule(
      ruleId: 'companion.sibling',
      predicate: 'required_companion',
      constructorIdentities: <String>{table},
      companionConstructorIdentities: <String>{companion},
      relation: 'sibling',
    );
    expect(
      evaluateGuardianUsageRule(siblingRule, evidence).status,
      GuardianUsageEvaluationStatus.allowed,
    );
  });

  test(
    'allowed parent distinguishes root, different, approved, and unknown',
    () {
      const rule = GuardianCompiledUsageRule(
        ruleId: 'inner.parents',
        predicate: 'allowed_parents',
        constructorIdentities: <String>{inner},
        parentConstructorIdentities: <String>{table},
      );
      final approved = GuardianUsageUnitEvidence(
        complete: true,
        invocations: <GuardianUsageInvocation>[
          invocation(table, 1),
          invocation(inner, 2, parentIndex: 0),
        ],
      );
      expect(
        evaluateGuardianUsageRule(rule, approved).status,
        GuardianUsageEvaluationStatus.allowed,
      );
      for (final evidence in <GuardianUsageUnitEvidence>[
        GuardianUsageUnitEvidence(
          complete: true,
          invocations: <GuardianUsageInvocation>[invocation(inner, 1)],
        ),
        GuardianUsageUnitEvidence(
          complete: true,
          invocations: <GuardianUsageInvocation>[
            invocation(outer, 1),
            invocation(inner, 2, parentIndex: 0),
          ],
        ),
      ]) {
        expect(
          evaluateGuardianUsageRule(rule, evidence).status,
          GuardianUsageEvaluationStatus.conflict,
        );
      }
      final unknown = GuardianUsageUnitEvidence(
        complete: true,
        invocations: <GuardianUsageInvocation>[
          invocation(inner, 1, parentResolved: false),
        ],
      );
      expect(
        evaluateGuardianUsageRule(rule, unknown).status,
        GuardianUsageEvaluationStatus.notAssessed,
      );
    },
  );

  test('variant context requires an exact mapped variant and honest scope', () {
    const rule = GuardianCompiledUsageRule(
      ruleId: 'button.variant',
      predicate: 'variant_context',
      constructorIdentities: <String>{inner},
      variantProperty: 'variant',
      variantIdentities: <String>{variant},
      allowedScopes: <String>{'widget_class'},
    );
    final allowed = GuardianUsageUnitEvidence(
      complete: true,
      invocations: <GuardianUsageInvocation>[
        invocation(
          inner,
          1,
          ownership: GuardianUsageOwnership.widgetClass,
          ownerScopeId: 'class:1',
          namedArgumentIdentities: const <String, String?>{'variant': variant},
        ),
      ],
    );
    expect(
      evaluateGuardianUsageRule(rule, allowed).status,
      GuardianUsageEvaluationStatus.allowed,
    );
    final outside = GuardianUsageUnitEvidence(
      complete: true,
      invocations: <GuardianUsageInvocation>[
        invocation(
          inner,
          1,
          namedArgumentIdentities: const <String, String?>{'variant': variant},
        ),
      ],
    );
    expect(
      evaluateGuardianUsageRule(rule, outside).status,
      GuardianUsageEvaluationStatus.conflict,
    );
    final unresolved = GuardianUsageUnitEvidence(
      complete: true,
      invocations: <GuardianUsageInvocation>[
        invocation(
          inner,
          1,
          namedArgumentIdentities: const <String, String?>{'variant': null},
        ),
      ],
    );
    expect(
      evaluateGuardianUsageRule(rule, unresolved).status,
      GuardianUsageEvaluationStatus.notAssessed,
    );
  });
}

final class _ResolvedOwnershipProbeRule extends AnalysisRule {
  _ResolvedOwnershipProbeRule()
    : super(
        name: code.lowerCaseName,
        description: 'Exercises analyzer-resolved Guardian ownership.',
      );

  static const LintCode code = LintCode(
    'guardian_test_usage_rule_ownership',
    'Invocation has analyzer-proven widget-class ownership.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    registry.addCompilationUnit(this, _ResolvedOwnershipProbeVisitor(this));
  }
}

final class _ResolvedOwnershipProbeVisitor extends SimpleAstVisitor<void> {
  _ResolvedOwnershipProbeVisitor(this.rule);

  final _ResolvedOwnershipProbeRule rule;

  @override
  void visitCompilationUnit(CompilationUnit node) {
    final evidence = buildGuardianUsageUnitEvidence(
      node,
      approvedMappedConstructorIdentities: const <String>{},
    );
    for (final invocation in evidence.invocations) {
      if (invocation.ownership == GuardianUsageOwnership.widgetClass &&
          invocation.node != null &&
          invocation.identity == 'package:test/test.dart#Target') {
        rule.reportAtNode(invocation.node!);
      }
    }
  }
}

@reflectiveTest
final class UsageRuleResolvedOwnershipTest extends AnalysisRuleTest {
  @override
  bool get addFlutterPackageDep => true;

  @override
  void setUp() {
    rule = _ResolvedOwnershipProbeRule();
    super.setUp();
  }

  Future<void>
  test_widgetStateAndNestedFunctionsAreOwnedButSuffixesAreNot() async {
    const source = r'''
import 'package:flutter/widgets.dart';

class Target extends StatelessWidget {
  const Target({super.key});
  @override
  Widget build(BuildContext context) => const SizedBox();
}

class HonestWidget extends StatelessWidget {
  const HonestWidget({super.key});
  @override
  Widget build(BuildContext context) {
    Widget local() => const Target();
    return local();
  }
}

class HonestStateful extends StatefulWidget {
  const HonestStateful({super.key});
  @override
  State<HonestStateful> createState() => HonestState();
}

class HonestState extends State<HonestStateful> {
  @override
  Widget build(BuildContext context) => const Target();
}

class MerelyHasWidgetSuffix {
  void build() {
    const Target();
  }
}
''';
    final first = source.indexOf('Target();', source.indexOf('Widget local'));
    final second = source.indexOf(
      'Target();',
      source.indexOf('class HonestState '),
    );
    await assertDiagnostics(source, [
      lint(first - 'const '.length, 'const Target()'.length),
      lint(second - 'const '.length, 'const Target()'.length),
    ]);
  }
}
