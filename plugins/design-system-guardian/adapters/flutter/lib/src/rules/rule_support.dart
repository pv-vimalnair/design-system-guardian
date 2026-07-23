import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/element/element.dart';

import '../config/adapter_config.dart';
import '../config/canonical_element_identity.dart';

GuardianAdapterConfig? validConfig(RuleContext context) =>
    GuardianAdapterConfigRepository.load(context).config;

bool isApprovedExpression(
  GuardianAdapterConfig config,
  String category,
  Expression expression,
) =>
    config.isApproved(category, canonicalExpressionIdentity(expression));

const visualDimensionArguments = <String>{
  'all',
  'blurRadius',
  'bottom',
  'crossAxisSpacing',
  'dimension',
  'elevation',
  'end',
  'endIndent',
  'extent',
  'gap',
  'height',
  'horizontal',
  'iconSize',
  'indent',
  'itemExtent',
  'left',
  'mainAxisSpacing',
  'margin',
  'maxHeight',
  'maxWidth',
  'minHeight',
  'minWidth',
  'padding',
  'right',
  'size',
  'spacing',
  'spreadRadius',
  'start',
  'strokeWidth',
  'thickness',
  'top',
  'vertical',
  'width',
};

const radiusArguments = <String>{
  'borderRadius',
  'bottomLeft',
  'bottomRight',
  'radius',
  'topLeft',
  'topRight',
};

const positionalDimensionArguments = <String, Set<int>>{
  'dart:ui#Offset': <int>{0, 1},
  'dart:ui#Size': <int>{0, 1},
  'package:flutter/src/painting/edge_insets.dart#EdgeInsets.all': <int>{0},
  'package:flutter/src/painting/edge_insets.dart#EdgeInsets.fromLTRB': <int>{0, 1, 2, 3},
  'package:flutter/src/painting/edge_insets.dart#EdgeInsets.only': <int>{0, 1, 2, 3},
};

const positionalRadiusArguments = <String, Set<int>>{
  'dart:ui#Radius.circular': <int>{0},
  'dart:ui#Radius.elliptical': <int>{0, 1},
  'package:flutter/src/painting/border_radius.dart#BorderRadius.circular': <int>{0},
  'package:flutter/src/painting/border_radius.dart#BorderRadius.horizontal': <int>{0, 1},
  'package:flutter/src/painting/border_radius.dart#BorderRadius.vertical': <int>{0, 1},
};

ExecutableElement? resolvedExecutable(Expression invocation) {
  final Element? element = switch (invocation) {
    InstanceCreationExpression node => node.constructorName.element,
    MethodInvocation node => node.methodName.element,
    FunctionExpressionInvocation node => node.element,
    _ => null,
  };
  return element is ExecutableElement ? element : null;
}

ArgumentList? _argumentList(Expression invocation) => switch (invocation) {
      InstanceCreationExpression node => node.argumentList,
      MethodInvocation node => node.argumentList,
      FunctionExpressionInvocation node => node.argumentList,
      _ => null,
    };

Iterable<({
  int index,
  String? parameterName,
  Expression expression,
  String? calleeIdentity,
  bool named,
})> governedArguments(Expression invocation) sync* {
  final argumentList = _argumentList(invocation);
  if (argumentList == null) return;
  final executable = resolvedExecutable(invocation);
  final positional = executable?.formalParameters
          .where((parameter) => parameter.isPositional)
          .toList(growable: false) ??
      const <FormalParameterElement>[];
  final calleeIdentity = canonicalElementIdentity(executable);
  var positionalIndex = 0;
  for (final argument in argumentList.arguments) {
    if (argument is NamedExpression) {
      yield (
        index: -1,
        parameterName: argument.name.label.name,
        expression: argument.expression,
        calleeIdentity: calleeIdentity,
        named: true,
      );
    } else {
      final name = positionalIndex < positional.length
          ? positional[positionalIndex].name
          : null;
      yield (
        index: positionalIndex,
        parameterName: name,
        expression: argument,
        calleeIdentity: calleeIdentity,
        named: false,
      );
      positionalIndex++;
    }
  }
}
