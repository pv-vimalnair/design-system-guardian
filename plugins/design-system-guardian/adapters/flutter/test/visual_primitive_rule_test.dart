import 'package:analyzer_testing/analysis_rule/analysis_rule.dart';
import 'package:design_system_guardian_flutter/src/rules/visual_primitive_rule.dart';
import 'package:test_reflective_loader/test_reflective_loader.dart';

void main() {
  defineReflectiveSuite(() {
    defineReflectiveTests(VisualPrimitiveRuleTest);
  });
}

@reflectiveTest
final class VisualPrimitiveRuleTest extends AnalysisRuleTest {
  @override
  bool get addFlutterPackageDep => true;

  @override
  void setUp() {
    rule = GuardianVisualPrimitiveRule();
    super.setUp();
    newFile(convertPath('/packages/ui/lib/ui.dart'), r'''
final class Paint {
  double strokeWidth = 0;
}

final class Path {}

final class Canvas {
  void drawPath(Path path, Paint paint) {}
  void clipPath(Path path) {}
  void saveLayer(Object? bounds, Paint paint) {}
}
''');
    newFile(
      convertPath('/packages/flutter/lib/src/rendering/custom_paint.dart'),
      'abstract class CustomPainter {}',
    );
    newFile(
      convertPath('/packages/flutter/lib/src/painting/image_resolution.dart'),
      'class AssetImage { const AssetImage(String name); }',
    );
    newFile(
      convertPath('/packages/flutter/lib/src/services/font_loader.dart'),
      'class FontLoader { FontLoader(String family); }',
    );
    newFile(
      convertPath('/packages/flutter/lib/src/widgets/image.dart'),
      'class Image { const Image.asset(String name); }',
    );
  }

  Future<void> test_paintSetterAndCascade_areRejected() async {
    const source = r'''
import 'dart:ui';

void mutate(Paint paint) {
  paint.strokeWidth = 2;
  Paint()..strokeWidth = 3;
}
''';
    const paintType = 'Paint paint';
    const setter = 'paint.strokeWidth';
    const constructor = 'Paint()';
    const cascadeSetter = '..strokeWidth';
    await assertDiagnostics(source, [
      lint(source.indexOf(paintType), 'Paint'.length),
      lint(source.indexOf(setter), setter.length),
      lint(source.indexOf(constructor), constructor.length),
      lint(source.indexOf(cascadeSetter), cascadeSetter.length),
    ]);
  }

  Future<void> test_resolvedDimensionAndRadiusSetters_areRejected() async {
    const source = r'''
class MutableVisualOptions {
  double _width = 0;
  double _radius = 0;

  set width(double value) => _width = value;
  set radius(double value) => _radius = value;
}

void mutate(MutableVisualOptions options) {
  options.width = 12;
  options..radius = 8;
}
''';
    const widthSetter = 'options.width';
    const radiusCascade = '..radius';
    await assertDiagnostics(source, [
      lint(source.indexOf(widthSetter), widthSetter.length),
      lint(source.indexOf(radiusCascade), radiusCascade.length),
    ]);
  }

  Future<void> test_customPainterSubclass_isRejected() async {
    const source = r'''
import 'package:flutter/src/rendering/custom_paint.dart';

abstract class BadPainter extends CustomPainter {}
''';
    const primitive = 'CustomPainter';
    await assertDiagnostics(source, [
      lint(source.indexOf(primitive), primitive.length),
    ]);
  }

  Future<void> test_rawImageAndFontAssets_areRejected() async {
    const source = r'''
import 'package:flutter/src/painting/image_resolution.dart';
import 'package:flutter/src/services/font_loader.dart';
import 'package:flutter/src/widgets/image.dart';

void loadRawAssets() {
  AssetImage('assets/raw.png');
  Image.asset('assets/raw.png');
  FontLoader('RawFont');
}
''';
    await assertDiagnostics(source, [
      for (final invocation in const <String>[
        "AssetImage('assets/raw.png')",
        "Image.asset('assets/raw.png')",
        "FontLoader('RawFont')",
      ])
        lint(source.indexOf(invocation), invocation.length),
      lint(source.indexOf('Image.asset') + 'Image.'.length, 'asset'.length),
    ]);
  }

  Future<void> test_canvasDrawClipAndSaveLayer_areRejected() async {
    const source = r'''
import 'dart:ui';

void draw(Canvas canvas, Path path, Paint paint) {
  canvas.drawPath(path, paint);
  canvas.clipPath(path);
  canvas.saveLayer(null, paint);
}
''';
    final diagnostics = [lint(source.indexOf('Canvas'), 'Canvas'.length)];
    for (final type in const <String>['Path', 'Paint']) {
      diagnostics.add(lint(source.indexOf(type), type.length));
    }
    for (final invocation in const <String>[
      'canvas.drawPath(path, paint)',
      'canvas.clipPath(path)',
      'canvas.saveLayer(null, paint)',
    ]) {
      diagnostics.add(lint(source.indexOf(invocation), invocation.length));
    }
    await assertDiagnostics(source, diagnostics);
  }
}
