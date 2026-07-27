import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/dart/element/type.dart';

import '../config/adapter_config.dart';
import '../config/canonical_element_identity.dart';
import 'rule_support.dart';

const _widgetIdentity = 'package:flutter/src/widgets/framework.dart#Widget';
const _stateIdentity = 'package:flutter/src/widgets/framework.dart#State';
const _incompleteGraphReason = 'incomplete_construction_graph';

enum GuardianUsageOwnership { widgetClass, outside, unresolved }

enum GuardianUsageEvaluationStatus { allowed, conflict, notAssessed }

final class GuardianUsageInvocation {
  const GuardianUsageInvocation({
    required this.identity,
    required this.sourceOffset,
    required this.sourceLength,
    required this.parentIndex,
    required this.parentResolved,
    required this.ownership,
    required this.ownerScopeId,
    required this.subtreeComplete,
    required this.namedArgumentIdentities,
    this.node,
  });

  final String identity;
  final int sourceOffset;
  final int sourceLength;
  final int? parentIndex;
  final bool parentResolved;
  final GuardianUsageOwnership ownership;
  final String? ownerScopeId;
  final bool subtreeComplete;
  final Map<String, String?> namedArgumentIdentities;
  final Expression? node;
}

final class GuardianUsageUnitEvidence {
  const GuardianUsageUnitEvidence({
    required this.complete,
    required this.invocations,
  });

  final bool complete;
  final List<GuardianUsageInvocation> invocations;
}

final class GuardianUsageRuleEvaluation {
  const GuardianUsageRuleEvaluation._({
    required this.ruleId,
    required this.status,
    required this.violationIndices,
    required this.reasonCode,
    required this.notAssessedIndex,
  });

  factory GuardianUsageRuleEvaluation.allowed(String ruleId) =>
      GuardianUsageRuleEvaluation._(
        ruleId: ruleId,
        status: GuardianUsageEvaluationStatus.allowed,
        violationIndices: const <int>[],
        reasonCode: null,
        notAssessedIndex: null,
      );

  factory GuardianUsageRuleEvaluation.conflict(
    String ruleId,
    Iterable<int> indices,
  ) => GuardianUsageRuleEvaluation._(
    ruleId: ruleId,
    status: GuardianUsageEvaluationStatus.conflict,
    violationIndices: List<int>.unmodifiable(indices.toSet().toList()..sort()),
    reasonCode: 'machine_rule_violation',
    notAssessedIndex: null,
  );

  factory GuardianUsageRuleEvaluation.notAssessed(
    String ruleId, {
    int? index,
  }) => GuardianUsageRuleEvaluation._(
    ruleId: ruleId,
    status: GuardianUsageEvaluationStatus.notAssessed,
    violationIndices: const <int>[],
    reasonCode: _incompleteGraphReason,
    notAssessedIndex: index,
  );

  final String ruleId;
  final GuardianUsageEvaluationStatus status;
  final List<int> violationIndices;
  final String? reasonCode;
  final int? notAssessedIndex;
}

GuardianUsageRuleEvaluation evaluateGuardianUsageRule(
  GuardianCompiledUsageRule rule,
  GuardianUsageUnitEvidence evidence,
) => switch (rule.predicate) {
  'forbidden_identity_in_scope' => _evaluateScoped(rule, evidence),
  'max_instances_per_scope' => _evaluateScoped(rule, evidence),
  'forbidden_nesting' => _evaluateForbiddenNesting(rule, evidence),
  'required_companion' => _evaluateRequiredCompanion(rule, evidence),
  'allowed_parents' => _evaluateAllowedParents(rule, evidence),
  'variant_context' => _evaluateVariantContext(rule, evidence),
  _ => GuardianUsageRuleEvaluation.notAssessed(rule.ruleId),
};

GuardianUsageRuleEvaluation _evaluateScoped(
  GuardianCompiledUsageRule rule,
  GuardianUsageUnitEvidence evidence,
) {
  final matches = <int>[];
  var unresolvedIndex = -1;
  for (var index = 0; index < evidence.invocations.length; index++) {
    final invocation = evidence.invocations[index];
    if (!rule.constructorIdentities.contains(invocation.identity)) continue;
    if (rule.scope == 'widget_class') {
      if (invocation.ownership == GuardianUsageOwnership.unresolved) {
        unresolvedIndex = unresolvedIndex < 0 ? index : unresolvedIndex;
        continue;
      }
      if (invocation.ownership != GuardianUsageOwnership.widgetClass) continue;
    }
    matches.add(index);
  }

  final violations = <int>[];
  if (rule.predicate == 'forbidden_identity_in_scope') {
    violations.addAll(matches);
  } else if (rule.scope == 'compilation_unit') {
    if (matches.length > rule.maximum) {
      violations.addAll(matches.skip(rule.maximum));
    }
  } else {
    final byOwner = <String, List<int>>{};
    for (final index in matches) {
      final owner = evidence.invocations[index].ownerScopeId;
      if (owner == null) {
        unresolvedIndex = unresolvedIndex < 0 ? index : unresolvedIndex;
        continue;
      }
      byOwner.putIfAbsent(owner, () => <int>[]).add(index);
    }
    for (final indices in byOwner.values) {
      if (indices.length > rule.maximum) {
        violations.addAll(indices.skip(rule.maximum));
      }
    }
  }
  if (violations.isNotEmpty) {
    return GuardianUsageRuleEvaluation.conflict(rule.ruleId, violations);
  }
  if (!evidence.complete || unresolvedIndex >= 0) {
    return GuardianUsageRuleEvaluation.notAssessed(
      rule.ruleId,
      index: unresolvedIndex < 0 ? null : unresolvedIndex,
    );
  }
  return GuardianUsageRuleEvaluation.allowed(rule.ruleId);
}

GuardianUsageRuleEvaluation _evaluateForbiddenNesting(
  GuardianCompiledUsageRule rule,
  GuardianUsageUnitEvidence evidence,
) {
  final violations = <int>[];
  int? incompleteIndex;
  for (var index = 0; index < evidence.invocations.length; index++) {
    final invocation = evidence.invocations[index];
    if (rule.outerConstructorIdentities.contains(invocation.identity) &&
        !invocation.subtreeComplete) {
      incompleteIndex ??= index;
    }
    if (!rule.innerConstructorIdentities.contains(invocation.identity)) {
      continue;
    }
    var cursor = index;
    final seen = <int>{};
    while (seen.add(cursor)) {
      final current = evidence.invocations[cursor];
      final parentIndex = current.parentIndex;
      if (parentIndex == null) {
        if (!current.parentResolved) incompleteIndex ??= index;
        break;
      }
      final parent = evidence.invocations[parentIndex];
      if (rule.outerConstructorIdentities.contains(parent.identity)) {
        violations.add(index);
        break;
      }
      cursor = parentIndex;
    }
  }
  if (violations.isNotEmpty) {
    return GuardianUsageRuleEvaluation.conflict(rule.ruleId, violations);
  }
  if (!evidence.complete || incompleteIndex != null) {
    return GuardianUsageRuleEvaluation.notAssessed(
      rule.ruleId,
      index: incompleteIndex,
    );
  }
  return GuardianUsageRuleEvaluation.allowed(rule.ruleId);
}

GuardianUsageRuleEvaluation _evaluateRequiredCompanion(
  GuardianCompiledUsageRule rule,
  GuardianUsageUnitEvidence evidence,
) {
  final violations = <int>[];
  int? incompleteIndex;
  for (var index = 0; index < evidence.invocations.length; index++) {
    final invocation = evidence.invocations[index];
    if (!rule.constructorIdentities.contains(invocation.identity)) continue;
    final relation = rule.relation;
    var found = false;
    var relationComplete = true;
    if (relation == 'child') {
      found = _childrenOf(index, evidence).any(
        (candidate) => rule.companionConstructorIdentities.contains(
          evidence.invocations[candidate].identity,
        ),
      );
      relationComplete = invocation.subtreeComplete;
    } else if (relation == 'descendant') {
      found = _descendantsOf(index, evidence).any(
        (candidate) => rule.companionConstructorIdentities.contains(
          evidence.invocations[candidate].identity,
        ),
      );
      relationComplete = invocation.subtreeComplete;
    } else {
      final parentIndex = invocation.parentIndex;
      if (parentIndex == null) {
        relationComplete = invocation.parentResolved && evidence.complete;
      } else {
        final parent = evidence.invocations[parentIndex];
        found = _childrenOf(parentIndex, evidence).any(
          (candidate) =>
              candidate != index &&
              rule.companionConstructorIdentities.contains(
                evidence.invocations[candidate].identity,
              ),
        );
        relationComplete = parent.subtreeComplete;
      }
    }
    if (found) continue;
    if (relationComplete) {
      violations.add(index);
    } else {
      incompleteIndex ??= index;
    }
  }
  if (violations.isNotEmpty) {
    return GuardianUsageRuleEvaluation.conflict(rule.ruleId, violations);
  }
  if (!evidence.complete || incompleteIndex != null) {
    return GuardianUsageRuleEvaluation.notAssessed(
      rule.ruleId,
      index: incompleteIndex,
    );
  }
  return GuardianUsageRuleEvaluation.allowed(rule.ruleId);
}

GuardianUsageRuleEvaluation _evaluateAllowedParents(
  GuardianCompiledUsageRule rule,
  GuardianUsageUnitEvidence evidence,
) {
  final violations = <int>[];
  int? incompleteIndex;
  for (var index = 0; index < evidence.invocations.length; index++) {
    final invocation = evidence.invocations[index];
    if (!rule.constructorIdentities.contains(invocation.identity)) continue;
    final parentIndex = invocation.parentIndex;
    if (parentIndex == null) {
      if (invocation.parentResolved) {
        violations.add(index);
      } else {
        incompleteIndex ??= index;
      }
      continue;
    }
    if (!rule.parentConstructorIdentities.contains(
      evidence.invocations[parentIndex].identity,
    )) {
      violations.add(index);
    }
  }
  if (violations.isNotEmpty) {
    return GuardianUsageRuleEvaluation.conflict(rule.ruleId, violations);
  }
  if (!evidence.complete || incompleteIndex != null) {
    return GuardianUsageRuleEvaluation.notAssessed(
      rule.ruleId,
      index: incompleteIndex,
    );
  }
  return GuardianUsageRuleEvaluation.allowed(rule.ruleId);
}

GuardianUsageRuleEvaluation _evaluateVariantContext(
  GuardianCompiledUsageRule rule,
  GuardianUsageUnitEvidence evidence,
) {
  final violations = <int>[];
  int? incompleteIndex;
  for (var index = 0; index < evidence.invocations.length; index++) {
    final invocation = evidence.invocations[index];
    if (!rule.constructorIdentities.contains(invocation.identity)) continue;
    final variant = invocation.namedArgumentIdentities[rule.variantProperty];
    if (variant == null) {
      incompleteIndex ??= index;
      continue;
    }
    if (!rule.variantIdentities.contains(variant)) continue;
    var allowed = false;
    var unresolved = false;
    if (rule.allowedScopes.contains('compilation_unit')) {
      if (evidence.complete) {
        allowed = true;
      } else {
        unresolved = true;
      }
    }
    if (rule.allowedScopes.contains('widget_class')) {
      if (invocation.ownership == GuardianUsageOwnership.widgetClass) {
        allowed = true;
      } else if (invocation.ownership == GuardianUsageOwnership.unresolved) {
        unresolved = true;
      }
    }
    if (allowed) continue;
    if (unresolved) {
      incompleteIndex ??= index;
    } else {
      violations.add(index);
    }
  }
  if (violations.isNotEmpty) {
    return GuardianUsageRuleEvaluation.conflict(rule.ruleId, violations);
  }
  if (!evidence.complete || incompleteIndex != null) {
    return GuardianUsageRuleEvaluation.notAssessed(
      rule.ruleId,
      index: incompleteIndex,
    );
  }
  return GuardianUsageRuleEvaluation.allowed(rule.ruleId);
}

Iterable<int> _childrenOf(
  int parentIndex,
  GuardianUsageUnitEvidence evidence,
) sync* {
  for (var index = 0; index < evidence.invocations.length; index++) {
    if (evidence.invocations[index].parentIndex == parentIndex) yield index;
  }
}

Iterable<int> _descendantsOf(
  int ancestorIndex,
  GuardianUsageUnitEvidence evidence,
) sync* {
  final pending = <int>[..._childrenOf(ancestorIndex, evidence)];
  final seen = <int>{};
  while (pending.isNotEmpty) {
    final index = pending.removeLast();
    if (!seen.add(index)) continue;
    yield index;
    pending.addAll(_childrenOf(index, evidence));
  }
}

GuardianUsageUnitEvidence buildGuardianUsageUnitEvidence(
  CompilationUnit unit, {
  required Set<String> approvedMappedConstructorIdentities,
}) {
  final collector = _ConstructionCollector(approvedMappedConstructorIdentities);
  unit.accept(collector);
  collector.expressions.sort((left, right) {
    final offset = left.offset.compareTo(right.offset);
    if (offset != 0) return offset;
    return left.length.compareTo(right.length);
  });
  final indices = <Expression, int>{
    for (var index = 0; index < collector.expressions.length; index++)
      collector.expressions[index]: index,
  };
  final ownership = <ClassDeclaration, GuardianUsageOwnership>{};
  final invocations = <GuardianUsageInvocation>[];
  for (final expression in collector.expressions) {
    final identity = canonicalExpressionIdentity(expression)!;
    final parent = _constructionParent(expression, indices);
    final declaration = expression.thisOrAncestorOfType<ClassDeclaration>();
    final resolvedOwnership = declaration == null
        ? GuardianUsageOwnership.outside
        : ownership.putIfAbsent(
            declaration,
            () => _classifyOwnership(declaration),
          );
    invocations.add(
      GuardianUsageInvocation(
        identity: identity,
        sourceOffset: expression.offset,
        sourceLength: expression.length,
        parentIndex: parent.index,
        parentResolved: parent.resolved,
        ownership: resolvedOwnership,
        ownerScopeId: resolvedOwnership == GuardianUsageOwnership.widgetClass
            ? 'class:' + declaration!.offset.toString()
            : null,
        subtreeComplete: _subtreeComplete(
          expression,
          approvedMappedConstructorIdentities,
        ),
        namedArgumentIdentities: _namedArgumentIdentities(expression),
        node: expression,
      ),
    );
  }
  return GuardianUsageUnitEvidence(
    complete: collector.complete,
    invocations: List<GuardianUsageInvocation>.unmodifiable(invocations),
  );
}

final class _ConstructionCollector extends RecursiveAstVisitor<void> {
  _ConstructionCollector(this.approvedIdentities);

  final Set<String> approvedIdentities;
  final List<Expression> expressions = <Expression>[];
  bool complete = true;

  void _record(Expression node, {required bool alwaysConstruction}) {
    final identity = canonicalExpressionIdentity(node);
    if (identity != null &&
        (alwaysConstruction || approvedIdentities.contains(identity))) {
      expressions.add(node);
      return;
    }
    if (identity == null || _typeMayContainWidget(node.staticType)) {
      complete = false;
    }
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _record(node, alwaysConstruction: true);
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    _record(node, alwaysConstruction: false);
    super.visitMethodInvocation(node);
  }

  @override
  void visitFunctionExpressionInvocation(FunctionExpressionInvocation node) {
    _record(node, alwaysConstruction: false);
    super.visitFunctionExpressionInvocation(node);
  }
}

({int? index, bool resolved}) _constructionParent(
  Expression child,
  Map<Expression, int> indices,
) {
  AstNode? cursor = child.parent;
  while (cursor != null) {
    if (cursor is Expression && _isInvocation(cursor)) {
      if (!_insideArguments(child, cursor)) {
        cursor = cursor.parent;
        continue;
      }
      final index = indices[cursor];
      if (index != null) return (index: index, resolved: true);
      return (index: null, resolved: false);
    }
    cursor = cursor.parent;
  }
  return (index: null, resolved: true);
}

bool _insideArguments(Expression child, Expression invocation) {
  final argumentList = switch (invocation) {
    InstanceCreationExpression node => node.argumentList,
    MethodInvocation node => node.argumentList,
    FunctionExpressionInvocation node => node.argumentList,
    _ => null,
  };
  if (argumentList == null) return false;
  AstNode? cursor = child;
  while (cursor != null && cursor != invocation) {
    if (identical(cursor, argumentList)) return true;
    cursor = cursor.parent;
  }
  return false;
}

bool _isInvocation(Expression node) =>
    node is InstanceCreationExpression ||
    node is MethodInvocation ||
    node is FunctionExpressionInvocation;

bool _subtreeComplete(
  Expression invocation,
  Set<String> approvedMappedConstructorIdentities,
) {
  final argumentList = switch (invocation) {
    InstanceCreationExpression node => node.argumentList,
    MethodInvocation node => node.argumentList,
    FunctionExpressionInvocation node => node.argumentList,
    _ => null,
  };
  if (argumentList == null) return false;
  final visitor = _ConstructionCompletenessVisitor(
    approvedMappedConstructorIdentities,
  );
  argumentList.accept(visitor);
  return visitor.complete;
}

final class _ConstructionCompletenessVisitor extends RecursiveAstVisitor<void> {
  _ConstructionCompletenessVisitor(this.approvedIdentities);

  final Set<String> approvedIdentities;
  bool complete = true;

  void _checkInvocation(Expression node, {required bool alwaysConstruction}) {
    final identity = canonicalExpressionIdentity(node);
    if (identity == null ||
        (!alwaysConstruction && !approvedIdentities.contains(identity))) {
      complete = false;
    }
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _checkInvocation(node, alwaysConstruction: true);
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    _checkInvocation(node, alwaysConstruction: false);
    super.visitMethodInvocation(node);
  }

  @override
  void visitFunctionExpressionInvocation(FunctionExpressionInvocation node) {
    _checkInvocation(node, alwaysConstruction: false);
    super.visitFunctionExpressionInvocation(node);
  }

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    if (_typeMayContainWidget(node.staticType) &&
        node.parent is! ConstructorName &&
        node.parent is! NamedType) {
      complete = false;
    }
    super.visitSimpleIdentifier(node);
  }
}

Map<String, String?> _namedArgumentIdentities(Expression invocation) {
  final output = <String, String?>{};
  for (final argument in governedArguments(invocation)) {
    final name = argument.parameterName;
    if (name != null && argument.named) {
      output[name] = canonicalExpressionIdentity(argument.expression);
    }
  }
  return Map<String, String?>.unmodifiable(output);
}

GuardianUsageOwnership _classifyOwnership(ClassDeclaration declaration) {
  final element = declaration.declaredFragment?.element;
  if (element == null) return GuardianUsageOwnership.unresolved;
  if (_declaredHierarchyIsUnresolved(declaration)) {
    return GuardianUsageOwnership.unresolved;
  }
  final types = <InterfaceType>[element.thisType, ...element.allSupertypes];
  if (types.any(
    (type) => canonicalElementIdentity(type.element) == _widgetIdentity,
  )) {
    return GuardianUsageOwnership.widgetClass;
  }
  for (final type in types) {
    if (canonicalElementIdentity(type.element) != _stateIdentity) continue;
    if (type.typeArguments.length != 1) {
      return GuardianUsageOwnership.unresolved;
    }
    final widgetType = type.typeArguments.single;
    if (widgetType is DynamicType || widgetType is InvalidType) {
      return GuardianUsageOwnership.unresolved;
    }
    if (canonicalTypeHierarchyIdentities(
      widgetType,
    ).contains(_widgetIdentity)) {
      return GuardianUsageOwnership.widgetClass;
    }
    return GuardianUsageOwnership.outside;
  }
  return GuardianUsageOwnership.outside;
}

bool _declaredHierarchyIsUnresolved(ClassDeclaration declaration) {
  final declaredTypes = <DartType?>[];
  final extendsClause = declaration.extendsClause;
  if (extendsClause != null) {
    declaredTypes.add(extendsClause.superclass.type);
  }
  declaredTypes.addAll(
    declaration.withClause?.mixinTypes.map((type) => type.type) ??
        const <DartType?>[],
  );
  declaredTypes.addAll(
    declaration.implementsClause?.interfaces.map((type) => type.type) ??
        const <DartType?>[],
  );
  return declaredTypes.any(
    (type) => type == null || type is DynamicType || type is InvalidType,
  );
}

bool _typeMayContainWidget(DartType? type) {
  if (type == null || type is DynamicType || type is InvalidType) return true;
  if (type is InterfaceType) {
    if (canonicalTypeHierarchyIdentities(type).contains(_widgetIdentity)) {
      return true;
    }
    return type.typeArguments.any(_typeMayContainWidget);
  }
  if (type is FunctionType) return _typeMayContainWidget(type.returnType);
  return false;
}
