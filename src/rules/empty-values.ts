import type { Rule } from '../types.js';
import { documentationOf } from './documentation.js';
import { specUrl } from '../spec.js';

/** Checks for empty string values in the [DOCUMENTATION] table. */
export const emptyStringValuesRule: Rule = {
  id: 'general/empty-string-value',
  category: 'general',
  severity: 'error',
  description: 'Flags empty string values in organization and documentation fields',
  run(ctx) {
    const documentation = documentationOf(ctx.doc);
    if (!documentation) return;

    for (const [key, value] of Object.entries(documentation)) {
      // Only check string values
      if (typeof value === 'string') {
        if (value.trim().length === 0) {
          ctx.report({
            rule: 'general/empty-string-value',
            category: 'general',
            message: `DOCUMENTATION.${key} is an empty string`,
            path: `DOCUMENTATION.${key}`,
            position: ctx.locate(`DOCUMENTATION.${key}`),
            helpUri: specUrl('organization-documentation'),
            suggestion: `Either omit the key or provide a non-empty value.`,
          });
        }
      }
    }
  },
};
