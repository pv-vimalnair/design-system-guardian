import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/dart/element/type.dart';
import 'package:analyzer/error/error.dart';

import '../config/adapter_config.dart';
import '../config/canonical_element_identity.dart';
import 'rule_support.dart';

/// Framework and community identities in these sets are raw capabilities, not
/// design-system mappings. They are denied before signed approval is consulted.
const _forbiddenVisualPrimitiveTypes = <String>{
  'dart:ui#Canvas',
  'dart:ui#Image',
  'dart:ui#Paint',
  'dart:ui#Paragraph',
  'dart:ui#Path',
  'dart:ui#PictureRecorder',
  'dart:ui#Shader',
  'package:flutter/src/painting/_network_image_io.dart#NetworkImage',
  'package:flutter/src/painting/decoration.dart#Decoration',
  'package:flutter/src/painting/image_provider.dart#FileImage',
  'package:flutter/src/painting/image_provider.dart#ImageProvider',
  'package:flutter/src/painting/image_provider.dart#MemoryImage',
  'package:flutter/src/painting/image_provider.dart#ResizeImage',
  'package:flutter/src/painting/image_resolution.dart#AssetImage',
  'package:flutter/src/rendering/custom_paint.dart#CustomPainter',
  'package:flutter/src/services/font_loader.dart#FontLoader',
  'package:flutter/src/widgets/basic.dart#RawImage',
  'package:flutter/src/widgets/image.dart#Image',
  'package:flutter_svg/src/loaders.dart#SvgAssetLoader',
  'package:flutter_svg/src/loaders.dart#SvgBytesLoader',
  'package:flutter_svg/src/loaders.dart#SvgFileLoader',
  'package:flutter_svg/src/loaders.dart#SvgNetworkLoader',
  'package:flutter_svg/src/loaders.dart#SvgStringLoader',
  'package:flutter_svg/src/widget.dart#SvgPicture',
};

const _forbiddenRawAssetEntryPoints = <String>{
  'dart:ui#ImageDescriptor.encoded',
  'dart:ui#ImageDescriptor.raw',
  'dart:ui#ImmutableBuffer.fromAsset',
  'dart:ui#decodeImageFromList',
  'dart:ui#instantiateImageCodec',
  'package:flutter/src/painting/image_provider.dart#FileImage',
  'package:flutter/src/painting/image_provider.dart#MemoryImage',
  'package:flutter/src/painting/image_provider.dart#ResizeImage',
  'package:flutter/src/painting/image_resolution.dart#AssetImage',
  'package:flutter/src/painting/_network_image_io.dart#NetworkImage',
  'package:flutter/src/services/asset_bundle.dart#AssetBundle.load',
  'package:flutter/src/services/asset_bundle.dart#AssetBundle.loadBuffer',
  'package:flutter/src/services/asset_bundle.dart#AssetBundle.loadString',
  'package:flutter/src/services/font_loader.dart#FontLoader',
  'package:flutter/src/services/font_loader.dart#FontLoader.addFont',
  'package:flutter/src/services/font_loader.dart#FontLoader.load',
  'package:flutter/src/widgets/image.dart#Image',
  'package:flutter/src/widgets/image.dart#Image.asset',
  'package:flutter/src/widgets/image.dart#Image.file',
  'package:flutter/src/widgets/image.dart#Image.memory',
  'package:flutter/src/widgets/image.dart#Image.network',
  'package:flutter_svg/src/loaders.dart#SvgAssetLoader',
  'package:flutter_svg/src/loaders.dart#SvgBytesLoader',
  'package:flutter_svg/src/loaders.dart#SvgFileLoader',
  'package:flutter_svg/src/loaders.dart#SvgNetworkLoader',
  'package:flutter_svg/src/loaders.dart#SvgStringLoader',
  'package:flutter_svg/src/widget.dart#SvgPicture',
  'package:flutter_svg/src/widget.dart#SvgPicture.asset',
  'package:flutter_svg/src/widget.dart#SvgPicture.file',
  'package:flutter_svg/src/widget.dart#SvgPicture.memory',
  'package:flutter_svg/src/widget.dart#SvgPicture.network',
  'package:flutter_svg/src/widget.dart#SvgPicture.string',
};

const _forbiddenCanvasOperations = <String>{
  'dart:ui#Canvas.clipPath',
  'dart:ui#Canvas.clipRRect',
  'dart:ui#Canvas.clipRSuperellipse',
  'dart:ui#Canvas.clipRect',
  'dart:ui#Canvas.drawArc',
  'dart:ui#Canvas.drawAtlas',
  'dart:ui#Canvas.drawCircle',
  'dart:ui#Canvas.drawColor',
  'dart:ui#Canvas.drawDRRect',
  'dart:ui#Canvas.drawImage',
  'dart:ui#Canvas.drawImageNine',
  'dart:ui#Canvas.drawImageRect',
  'dart:ui#Canvas.drawLine',
  'dart:ui#Canvas.drawOval',
  'dart:ui#Canvas.drawPaint',
  'dart:ui#Canvas.drawParagraph',
  'dart:ui#Canvas.drawPath',
  'dart:ui#Canvas.drawPicture',
  'dart:ui#Canvas.drawPoints',
  'dart:ui#Canvas.drawRRect',
  'dart:ui#Canvas.drawRSuperellipse',
  'dart:ui#Canvas.drawRawAtlas',
  'dart:ui#Canvas.drawRect',
  'dart:ui#Canvas.drawShadow',
  'dart:ui#Canvas.drawVertices',
  'dart:ui#Canvas.saveLayer',
};

const _forbiddenMutablePrimitiveMembers = <String>{
  'dart:ui#Paint.blendMode',
  'dart:ui#Paint.blendMode=',
  'dart:ui#Paint.color',
  'dart:ui#Paint.color=',
  'dart:ui#Paint.colorFilter',
  'dart:ui#Paint.colorFilter=',
  'dart:ui#Paint.filterQuality',
  'dart:ui#Paint.filterQuality=',
  'dart:ui#Paint.imageFilter',
  'dart:ui#Paint.imageFilter=',
  'dart:ui#Paint.invertColors',
  'dart:ui#Paint.invertColors=',
  'dart:ui#Paint.isAntiAlias',
  'dart:ui#Paint.isAntiAlias=',
  'dart:ui#Paint.maskFilter',
  'dart:ui#Paint.maskFilter=',
  'dart:ui#Paint.shader',
  'dart:ui#Paint.shader=',
  'dart:ui#Paint.strokeCap',
  'dart:ui#Paint.strokeCap=',
  'dart:ui#Paint.strokeJoin',
  'dart:ui#Paint.strokeJoin=',
  'dart:ui#Paint.strokeMiterLimit',
  'dart:ui#Paint.strokeMiterLimit=',
  'dart:ui#Paint.strokeWidth',
  'dart:ui#Paint.strokeWidth=',
  'dart:ui#Paint.style',
  'dart:ui#Paint.style=',
  'dart:ui#Path.fillType',
  'dart:ui#Path.fillType=',
};

const _approvedWrapperCategories = <String>{
  'colors',
  'textStyles',
  'icons',
  'dimensions',
  'effects',
  'motion',
  'widgets',
};

bool _hasForbiddenVisualPrimitiveType(DartType? type) =>
    canonicalTypeHierarchyIdentities(
      type,
    ).any(_forbiddenVisualPrimitiveTypes.contains);

bool _isForbiddenResolvedIdentity(String? identity) =>
    identity != null &&
    (_forbiddenVisualPrimitiveTypes.contains(identity) ||
        _forbiddenRawAssetEntryPoints.contains(identity) ||
        _forbiddenCanvasOperations.contains(identity) ||
        _forbiddenMutablePrimitiveMembers.contains(identity));

bool _isApprovedDesignSystemWrapper(
  GuardianAdapterConfig? config,
  String? identity,
) {
  if (config == null ||
      identity == null ||
      isFrameworkDefaultIdentity(identity) ||
      _isForbiddenResolvedIdentity(identity)) {
    return false;
  }
  return _approvedWrapperCategories.any(
    (category) => config.isApproved(category, identity),
  );
}

String? _setterName(String? elementName) {
  if (elementName == null || elementName.isEmpty) return null;
  return elementName.endsWith('=')
      ? elementName.substring(0, elementName.length - 1)
      : elementName;
}

final class GuardianVisualPrimitiveRule extends AnalysisRule {
  GuardianVisualPrimitiveRule()
    : super(
        name: code.name,
        description:
            'Rejects raw drawing, custom painting, and unapproved visual assets.',
      );

  static const LintCode code = LintCode(
    'guardian_unapproved_visual_primitive',
    'Visual primitive must be an exact signed design-system wrapper identity.',
    correctionMessage:
        'Use an approved design-system primitive or a Guardian missing-asset sentinel.',
  );

  @override
  LintCode get diagnosticCode => code;

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    final visitor = _VisualPrimitiveVisitor(this, context);
    registry.addInstanceCreationExpression(this, visitor);
    registry.addMethodInvocation(this, visitor);
    registry.addFunctionExpressionInvocation(this, visitor);
    registry.addPrefixedIdentifier(this, visitor);
    registry.addPropertyAccess(this, visitor);
    registry.addSimpleIdentifier(this, visitor);
    registry.addClassDeclaration(this, visitor);
    registry.addNamedType(this, visitor);
    registry.addAssignmentExpression(this, visitor);
  }
}

final class _VisualPrimitiveVisitor extends SimpleAstVisitor<void> {
  _VisualPrimitiveVisitor(this.rule, this.context);

  final GuardianVisualPrimitiveRule rule;
  final RuleContext context;

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) =>
      _checkInvocation(node);

  @override
  void visitMethodInvocation(MethodInvocation node) {
    _checkInvocation(node, receiverType: node.realTarget?.staticType);
  }

  @override
  void visitFunctionExpressionInvocation(FunctionExpressionInvocation node) =>
      _checkInvocation(node);

  @override
  void visitPrefixedIdentifier(PrefixedIdentifier node) {
    if (_isAssignmentLeftHandSide(node)) return;
    _checkResolvedReference(node);
  }

  @override
  void visitPropertyAccess(PropertyAccess node) {
    if (_isAssignmentLeftHandSide(node)) return;
    _checkResolvedReference(node);
  }

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    final parent = node.parent;
    if (_isAssignmentLeftHandSide(node) ||
        parent is PrefixedIdentifier ||
        parent is PropertyAccess ||
        (parent is MethodInvocation &&
            (identical(parent.methodName, node) ||
                identical(parent.target, node)))) {
      return;
    }
    _checkResolvedReference(node);
  }

  @override
  void visitClassDeclaration(ClassDeclaration node) {
    final inheritedTypes = <NamedType>[
      if (node.extendsClause case final clause?) clause.superclass,
      ...?node.withClause?.mixinTypes,
      ...?node.implementsClause?.interfaces,
    ];
    for (final inherited in inheritedTypes) {
      if (_hasForbiddenVisualPrimitiveType(inherited.type)) {
        rule.reportAtNode(inherited);
        return;
      }
    }
  }

  @override
  void visitNamedType(NamedType node) {
    final parent = node.parent;
    if (parent is ConstructorName ||
        parent is ExtendsClause ||
        parent is WithClause ||
        parent is ImplementsClause) {
      return;
    }
    if (!_hasForbiddenVisualPrimitiveType(node.type)) return;
    final identity = canonicalElementIdentity(node.element);
    if (_isForbiddenResolvedIdentity(identity)) {
      rule.reportAtNode(node);
      return;
    }
    final config = validConfig(context);
    if (!_isApprovedDesignSystemWrapper(config, identity)) {
      rule.reportAtNode(node);
    }
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    final writeElement = node.writeElement;
    final writeIdentity = canonicalElementIdentity(writeElement);
    if (_isForbiddenResolvedIdentity(writeIdentity)) {
      rule.reportAtNode(node.leftHandSide);
      return;
    }

    // Name classification is only applied after the analyzer resolves a real
    // setter. Source spelling alone can never trigger or satisfy this check.
    final property = _setterName(writeElement?.name);
    if (property == null ||
        (!visualDimensionArguments.contains(property) &&
            !radiusArguments.contains(property))) {
      return;
    }
    final config = validConfig(context);
    final valueIdentity = canonicalExpressionIdentity(node.rightHandSide);
    final exactSignedSetter = _isApprovedDesignSystemWrapper(
      config,
      writeIdentity,
    );
    final exactSignedValue =
        config?.isApproved('dimensions', valueIdentity) ?? false;
    if (!exactSignedSetter || !exactSignedValue) {
      rule.reportAtNode(node.leftHandSide);
    }
  }

  bool _isAssignmentLeftHandSide(Expression node) {
    final parent = node.parent;
    return parent is AssignmentExpression &&
        identical(parent.leftHandSide, node);
  }

  void _checkResolvedReference(Expression node) {
    final identity = canonicalExpressionIdentity(node);
    if (_isForbiddenResolvedIdentity(identity)) {
      rule.reportAtNode(node);
    }
  }

  void _checkInvocation(Expression node, {DartType? receiverType}) {
    final identity = canonicalExpressionIdentity(node);
    if (_isForbiddenResolvedIdentity(identity)) {
      rule.reportAtNode(node);
      return;
    }

    final returnsRawPrimitive = _hasForbiddenVisualPrimitiveType(
      node.staticType,
    );
    final invokesRawPrimitive = _hasForbiddenVisualPrimitiveType(receiverType);
    if (!returnsRawPrimitive && !invokesRawPrimitive) return;

    final config = validConfig(context);
    if (_isApprovedDesignSystemWrapper(config, identity)) return;
    rule.reportAtNode(node);
  }
}
