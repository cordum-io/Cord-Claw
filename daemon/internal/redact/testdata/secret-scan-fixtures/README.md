# Gitleaks negative fixture

`TestBenignCorpusScanner_FailsOnSecret` generates the fake secret-shaped
fixture in a temporary directory at test runtime.

Do not commit token-shaped strings here. GitHub push protection correctly
blocks committed secret-like fixtures, even when they are fake.
