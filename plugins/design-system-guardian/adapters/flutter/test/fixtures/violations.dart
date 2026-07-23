import 'package:flutter/material.dart';

// ignore: design_system_guardian_flutter/guardian_unapproved_icon
Widget violatingFixture() {
  return Container(
    width: 12,
    color: const Color(0xFF0066FF),
    decoration: BoxDecoration(
      borderRadius: BorderRadius.circular(7),
      boxShadow: const <BoxShadow>[
        BoxShadow(blurRadius: 8, spreadRadius: 2),
      ],
    ),
    child: Column(
      children: <Widget>[
        const Icon(Icons.add),
        const Text('Unapproved', style: TextStyle(fontSize: 14)),
        Card(child: SizedBox(width: 12, height: 12)),
        AnimatedOpacity(
          opacity: 1,
          duration: const Duration(milliseconds: 240),
          child: const SizedBox.shrink(),
        ),
      ],
    ),
  );
}
