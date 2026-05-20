const NAME_SUFFIX_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;

export function physicalName(baseName: string): string {
  const suffix = process.env.AEGISFLOW_NAME_SUFFIX?.trim();
  if (!suffix) {
    return baseName;
  }
  if (!NAME_SUFFIX_PATTERN.test(suffix)) {
    throw new Error(
      'AEGISFLOW_NAME_SUFFIX must start with an alphanumeric character and contain only letters, numbers, hyphens, or underscores.',
    );
  }
  return `${baseName}-${suffix}`;
}
