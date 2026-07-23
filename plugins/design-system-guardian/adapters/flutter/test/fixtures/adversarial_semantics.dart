import 'package:design_system_guardian_flutter/design_system_guardian_flutter.dart';
import 'package:flutter/material.dart';

class WrappedColor extends Color {
  const WrappedColor(super.value);
}

final class AppWidgets {
  static const staticCard = SizedBox.shrink();
}

Widget componentFactory({Object? variant}) => const SizedBox.shrink();

Widget adversarial(Animation<double> parent) => Column(
      children: <Widget>[
        ColoredBox(color: const WrappedColor(0xFF123456)),
        DecoratedBox(
          decoration: BoxDecoration(
            gradient: const LinearGradient(colors: <Color>[Colors.red, Colors.blue]),
            border: Border.all(color: Colors.red),
            backgroundBlendMode: BlendMode.srcOver,
          ),
        ),
        ColorFiltered(
          colorFilter: const ColorFilter.mode(Colors.red, BlendMode.srcIn),
          child: AppWidgets.staticCard,
        ),
        componentFactory(variant: Object()),
        Padding(padding: const EdgeInsets.all(13), child: const SizedBox()),
        ClipRRect(
          borderRadius: BorderRadius.circular(7),
          child: const SizedBox(),
        ),
        GuardianMissingSentinel(
          kind: GuardianMissingKind.icon,
          requestId: 'LOOKALIKE-OR-UNBOUND',
          policyDigest: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
      ],
    );

final curved = CurvedAnimation(parent: const AlwaysStoppedAnimation(0), curve: const Cubic(0, 0, 1, 1));
final colorTween = ColorTween(begin: Colors.red, end: Colors.blue);
