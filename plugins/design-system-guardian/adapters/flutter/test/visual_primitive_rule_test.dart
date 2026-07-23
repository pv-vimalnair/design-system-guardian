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
import 'package:flutter/rendering.dart';

abstract class BadPainter extends CustomPainter {}
''';
    const primitive = 'CustomPainter';
    await assertDiagnostics(source, [
      lint(source.indexOf(primitive), primitive.length),
    ]);
  }

  Future<void> test_rawImageAndFontAssets_areRejected() async {
    const source = r'''
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

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
    final diagnostics = <ExpectedDiagnostic>[];
    for (final type in const <String>['Canvas', 'Path', 'Paint']) {
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
