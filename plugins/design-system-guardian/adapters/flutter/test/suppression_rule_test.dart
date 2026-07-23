import 'package:analyzer_testing/analysis_rule/analysis_rule.dart';
import 'package:design_system_guardian_flutter/src/rules/suppression_rule.dart';
import 'package:test_reflective_loader/test_reflective_loader.dart';

void main() {
  defineReflectiveSuite(() {
    defineReflectiveTests(GuardianSuppressionRuleTest);
  });
}

@reflectiveTest
final class GuardianSuppressionRuleTest extends AnalysisRuleTest {
  @override
  void setUp() {
    rule = GuardianSuppressionRule();
    super.setUp();
  }

  Future<void> test_adversarialSuppression_isRejected() async {
    await assertDiagnostics(
      r'''
// ignore: design_system_guardian_flutter/guardian_unapproved_color
void f() {}
''',
      [
        lint(
          0,
          67,
          messageContains: 'cannot be suppressed',
        ),
      ],
    );
  }

  Future<void> test_ordinaryComment_isApprovedCounterpart() async {
    await assertNoDiagnostics(r'''
// The exact approved token is selected by the bound catalog.
void f() {}
''');
  }
}
