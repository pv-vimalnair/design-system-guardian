import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';
import 'package:analyzer_testing/analysis_rule/analysis_rule.dart';
import 'package:design_system_guardian_flutter/src/config/canonical_element_identity.dart';
import 'package:test_reflective_loader/test_reflective_loader.dart';

void main() {
  defineReflectiveSuite(() {
    defineReflectiveTests(ResolvedTypeHierarchyTest);
  });
}

/// A deliberately small analyzer-testing probe for the production resolved-type
/// classifier. The production category rules additionally apply catalog approval;
/// this test protects the hierarchy boundary that wrappers previously bypassed.
final class _GovernedTypeProbeRule extends AnalysisRule {
  _GovernedTypeProbeRule()
    : super(
        name: code.lowerCaseName,
        description: 'Exercises Guardian resolved-type classification.',
      );

  static const LintCode code = LintCode(
    'guardian_test_governed_type_probe',
    'Resolved expression is governed by the {0} category.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    registry.addInstanceCreationExpression(
      this,
      _GovernedTypeProbeVisitor(this),
    );
  }
}

final class _GovernedTypeProbeVisitor extends SimpleAstVisitor<void> {
  _GovernedTypeProbeVisitor(this.rule);

  final _GovernedTypeProbeRule rule;

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    for (final category in const <String>['colors', 'effects', 'motion']) {
      if (expressionHasGovernedType(node, category)) {
        rule.reportAtNode(node, arguments: <Object>[category]);
        return;
      }
    }
  }
}

@reflectiveTest
final class ResolvedTypeHierarchyTest extends AnalysisRuleTest {
  @override
  bool get addFlutterPackageDep => true;

  @override
  void setUp() {
    rule = _GovernedTypeProbeRule();
    super.setUp();
  }

  Future<void> test_adversarialWrappersAndVisualTypes_areGoverned() async {
    const source = r'''
import 'package:flutter/material.dart';

class WrappedColor extends Color {
  const WrappedColor(super.value);
}

void bad() {
  const WrappedColor(0xff000000);
  const BoxDecoration();
  const Duration(milliseconds: 1);
}
''';
    const wrapped = 'const WrappedColor(0xff000000)';
    const decoration = 'const BoxDecoration()';
    const motion = 'const Duration(milliseconds: 1)';
    await assertDiagnostics(source, [
      lint(source.indexOf(wrapped), wrapped.length),
      lint(source.indexOf(decoration), decoration.length),
      lint(source.indexOf(motion), motion.length),
    ]);
  }

  Future<void> test_nonVisualConstructor_isApprovedCounterpart() async {
    await assertNoDiagnostics(r'''
class Harmless {
  const Harmless();
}

void okay() {
  const Harmless();
}
''');
  }
}
