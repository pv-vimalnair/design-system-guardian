import 'package:flutter/widgets.dart';
import 'package:example_company_design_system/example_company_design_system.dart';

Widget approvedFixture() {
  return ApprovedCard(
    variant: ApprovedCardVariant.primary,
    color: AppColors.primary,
    textStyle: AppTypography.body,
    icon: AppIcons.add,
    spacing: AppSpacing.medium,
    effect: AppEffects.card,
    motion: AppMotion.standard,
  );
}
