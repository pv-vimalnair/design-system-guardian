import 'package:flutter/widgets.dart';

enum GuardianMissingKind {
  icon('MISSING ICON'),
  color('MISSING COLOR'),
  textStyle('MISSING TEXT STYLE'),
  component('MISSING COMPONENT'),
  token('MISSING TOKEN');

  const GuardianMissingKind(this.label);

  final String label;
}

/// The sole fixed visual exception permitted by Guardian policy.
///
/// It is intentionally conspicuous, always carries provenance, and is never a
/// production-ready substitute. Do not copy, restyle, wrap, or recreate it.
final class GuardianMissingSentinel extends StatelessWidget {
  const GuardianMissingSentinel({
    required this.kind,
    required this.requestId,
    required this.policyDigest,
    super.key,
  })  : assert(requestId != ''),
        assert(policyDigest != '');

  static const namespace = 'design_system_guardian.sentinel.v1';
  static const manifestDigest =
      '102743bb7512a31cfcffef46885c4b34076b9a0575a0711e0a0f1127cb105f79';
  static const productionReady = false;
  static const automaticPromotion = false;

  static const background = Color(0xFFFF00FF);
  static const border = Color(0xFF00FFFF);
  static const foreground = Color(0xFF000000);

  final GuardianMissingKind kind;
  final String requestId;
  final String policyDigest;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      container: true,
      label: '${kind.label}; request $requestId; policy $policyDigest; not production ready',
      child: CustomPaint(
        painter: const _DiagonalStripePainter(),
        child: ConstrainedBox(
          constraints: const BoxConstraints(minWidth: 180, minHeight: 96),
          child: DecoratedBox(
            decoration: BoxDecoration(
              border: Border.all(color: border, width: 4),
            ),
            child: Padding(
              padding: const EdgeInsets.all(10),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Text(
                    kind.label,
                    style: const TextStyle(
                      color: foreground,
                      fontFamily: 'monospace',
                      fontSize: 14,
                      fontWeight: FontWeight.w900,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    'requestId=$requestId\npolicyDigest=$policyDigest',
                    style: const TextStyle(
                      color: foreground,
                      fontFamily: 'monospace',
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

final class _DiagonalStripePainter extends CustomPainter {
  const _DiagonalStripePainter();

  @override
  void paint(Canvas canvas, Size size) {
    canvas.drawRect(Offset.zero & size, Paint()..color = GuardianMissingSentinel.background);
    final stripe = Paint()
      ..color = GuardianMissingSentinel.border
      ..strokeWidth = 6;
    for (double offset = -size.height; offset < size.width; offset += 24) {
      canvas.drawLine(
        Offset(offset, size.height),
        Offset(offset + size.height, 0),
        stripe,
      );
    }
  }

  @override
  bool shouldRepaint(covariant _DiagonalStripePainter oldDelegate) => false;
}
