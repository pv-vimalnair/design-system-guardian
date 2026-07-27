import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/element/element.dart';
import 'package:analyzer/dart/element/type.dart';

/// Builds a stable code identity from resolved analyzer elements.
///
/// Source spelling, import prefixes, display values, and class-name guesses are
/// deliberately excluded. Unresolved elements return `null` and therefore can
/// never be approved.
String? canonicalElementIdentity(Element? element) {
  if (element == null) return null;
  final library = element.library;
  if (library == null) return null;
  final uri = library.firstFragment.source.uri.toString();
  if (!uri.startsWith('package:') && !uri.startsWith('dart:')) return null;

  final names = <String>[];
  Element? cursor = element;
  while (cursor != null && cursor is! LibraryElement) {
    final name = cursor.name;
    final unnamedConstructor = cursor is ConstructorElement && name == 'new';
    if (!unnamedConstructor &&
        name != null &&
        name.isNotEmpty &&
        (names.isEmpty || names.last != name)) {
      names.add(name);
    }
    cursor = cursor.enclosingElement;
  }
  if (names.isEmpty) return null;
  return '$uri#${names.reversed.join('.')}';
}

String? canonicalExpressionIdentity(Expression expression) {
  final unwrapped = expression.unParenthesized;
  return switch (unwrapped) {
    InstanceCreationExpression node => canonicalElementIdentity(
      node.constructorName.element,
    ),
    MethodInvocation node => canonicalElementIdentity(node.methodName.element),
    FunctionExpressionInvocation node =>
      canonicalElementIdentity(node.element) ??
          canonicalExpressionIdentity(node.function),
    PrefixedIdentifier node => canonicalElementIdentity(
      node.identifier.element,
    ),
    PropertyAccess node => canonicalElementIdentity(node.propertyName.element),
    SimpleIdentifier node => canonicalElementIdentity(node.element),
    NamedArgument node => canonicalExpressionIdentity(node.argumentExpression),
    _ => null,
  };
}

const governedTypeIdentities = <String, Set<String>>{
  'colors': <String>{'dart:ui#Color'},
  'textStyles': <String>{
    'package:flutter/src/painting/text_style.dart#TextStyle',
  },
  'icons': <String>{'package:flutter/src/widgets/icon_data.dart#IconData'},
  'effects': <String>{
    'dart:ui#BlendMode',
    'dart:ui#BlurStyle',
    'dart:ui#ColorFilter',
    'dart:ui#ImageFilter',
    'dart:ui#MaskFilter',
    'dart:ui#Shader',
    'package:flutter/src/painting/borders.dart#ShapeBorder',
    'package:flutter/src/painting/box_border.dart#BoxBorder',
    'package:flutter/src/painting/box_shadow.dart#BoxShadow',
    'package:flutter/src/painting/decoration.dart#Decoration',
    'package:flutter/src/painting/gradient.dart#Gradient',
    'package:flutter/src/painting/shadow.dart#Shadow',
    'package:flutter/src/widgets/basic.dart#BackdropFilter',
  },
  'motion': <String>{
    'dart:core#Duration',
    'package:flutter/src/animation/animation.dart#Animation',
    'package:flutter/src/animation/animation_controller.dart#AnimationController',
    'package:flutter/src/animation/animations.dart#CurvedAnimation',
    'package:flutter/src/animation/curves.dart#Cubic',
    'package:flutter/src/animation/curves.dart#Curve',
    'package:flutter/src/animation/tween.dart#Animatable',
    'package:flutter/src/animation/tween.dart#ColorTween',
    'package:flutter/src/animation/tween.dart#Tween',
    'package:flutter/src/physics/spring_simulation.dart#SpringDescription',
  },
  'widgets': <String>{'package:flutter/src/widgets/framework.dart#Widget'},
};

Set<String> canonicalTypeHierarchyIdentities(DartType? type) {
  if (type is! InterfaceType) return const <String>{};
  final output = <String>{};
  final direct = canonicalElementIdentity(type.element);
  if (direct != null) output.add(direct);
  for (final supertype in type.allSupertypes) {
    final identity = canonicalElementIdentity(supertype.element);
    if (identity != null) output.add(identity);
  }
  return output;
}

bool expressionHasGovernedType(Expression expression, String category) {
  final governed = governedTypeIdentities[category];
  if (governed == null) return false;
  final resolved = canonicalTypeHierarchyIdentities(expression.staticType);
  return resolved.any(governed.contains);
}

bool expressionIsWidget(Expression expression) =>
    expressionHasGovernedType(expression, 'widgets');

bool isFrameworkDefaultIdentity(String? identity) =>
    identity != null &&
    (identity.startsWith('dart:') || identity.startsWith('package:flutter/'));

const guardianSentinelIdentity =
    'package:design_system_guardian_flutter/src/sentinels/guardian_missing_sentinel.dart#GuardianMissingSentinel';

bool isGuardianSentinelIdentity(String? identity) =>
    identity == guardianSentinelIdentity;
