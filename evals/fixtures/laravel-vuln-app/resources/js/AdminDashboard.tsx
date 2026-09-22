// Fixture: React noise — NOT Blade. `aria-invalid={!!errors.body}` is JSX
// double-negation; it is why laravel-security Step 4 globs to *.blade.php.
// A bare raw-echo scan (no glob) hits this file and buries real Blade sinks.
export function ReviewField({ errors }: { errors: Record<string, string[]> }) {
  return <input name="body" aria-invalid={!!errors.body} className="input" />;
}
