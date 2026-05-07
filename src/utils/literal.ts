// Helpers for distinguishing literal values from Terraform expressions in
// hcl2json output. hcl2json emits non-literal scalars (booleans, numbers,
// strings driven by var/local/data/module references) as strings - either
// `"${var.x}"` for interpolation or `"var.x"` for bare refs.
//
// Rules that branch on `value === true/false` or `typeof value === 'number'`
// silently treat these as "unset", which leads to incorrect PASS/WARN/FAIL
// verdicts when the value is actually expression-driven. Use these helpers
// before evaluating to surface INCONCLUSIVE instead.

const BARE_REF = /^(var|local|data|module)\./;

// True when v is a string carrying a Terraform expression we cannot resolve
// here. Use for boolean/number fields where hcl2json would have produced a
// real boolean/number if the source were literal.
export function isUnresolvedScalar(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  if (v.includes('${')) return true;
  return BARE_REF.test(v);
}

// True when v is a non-empty string that is NOT a Terraform expression.
// Use for string fields where any literal string is acceptable but we
// must reject `"${var.x}"` etc.
export function isLiteralString(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  if (v.trim() === '') return false;
  return !isUnresolvedScalar(v);
}
