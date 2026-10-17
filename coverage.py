import sys

from pathlib import Path

(baseline, onlySummary) = sys.argv[1:]

lines = Path('lcov.info').read_text().splitlines()

lf = sum(int(line[3:]) for line in lines if line.startswith('LF:'))

lh = sum(int(line[3:]) for line in lines if line.startswith('LH:'))

pct = (lh / lf * 100) if lf else 0.0

if onlySummary:
    print(f'coverage: {pct:.2f}% ({lh}/{lf})')
else:
    print(f'coverage: {pct:.2f}% ({lh}/{lf}), baseline: {baseline:.2f}%')
    sys.exit(0 if pct >= baseline else 1)