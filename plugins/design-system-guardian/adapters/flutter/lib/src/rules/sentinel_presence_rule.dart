import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import '../config/canonical_element_identity.dart';
import '../sentinels/sentinel_evidence.dart';
import 'rule_support.dart';

final class GuardianSentinelPresenceRule extends AnalysisRule {
  GuardianSentinelPresenceRule()
    : super(
        name: code.name,
        description:
            'Makes every fixed diagnostic sentinel fail production readiness.',
      );

  static const LintCode code = LintCode(
    'guardian_sentinel_present',
    'Guardian diagnostic sentinel is present; {0}. This build is not production ready.',
    correctionMessage:
        'Fulfil the linked design-system request, then replace the sentinel with that exact approved identity.',
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
      _SentinelPresenceVisitor(this, context),
    );
  }
}

final class _SentinelPresenceVisitor extends SimpleAstVisitor<void> {
  _SentinelPresenceVisitor(this.rule, this.context);

  final GuardianSentinelPresenceRule rule;
  final RuleContext context;

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    final identity = canonicalElementIdentity(node.constructorName.element);
    if (!isGuardianSentinelIdentity(identity)) return;
    final config = validConfig(context);
    var valid = false;
    if (config != null) {
      final arguments = <String, Expression>{};
      for (final argument in node.argumentList.arguments) {
        if (argument is NamedExpression) {
          arguments[argument.name.label.name] = argument.expression;
        }
      }
      final requestExpression = arguments['requestId'];
      final policyExpression = arguments['policyDigest'];
      final kindExpression = arguments['kind'];
      final requestId = requestExpression is SimpleStringLiteral
          ? requestExpression.value
          : null;
      final policyDigest = policyExpression is SimpleStringLiteral
          ? policyExpression.value
          : null;
      final kindIdentity = kindExpression == null
          ? null
          : canonicalExpressionIdentity(kindExpression);
      final evidence = GuardianSentinelEvidenceRepository.load(config);
      valid =
          requestId != null &&
          requestId.isNotEmpty &&
          policyDigest == config.policyDigest &&
          kindIdentity != null &&
          evidence.matches(
            requestId: requestId,
            kindIdentity: kindIdentity,
            policyDigest: policyDigest!,
          );
    }
    final status = valid
        ? 'it is bound to exact host-supplied request, policy, and kind evidence'
        : 'it is malformed or is not bound to exact host-supplied sentinel evidence';
    rule.reportAtNode(node.constructorName, arguments: <Object>[status]);
  }
}
