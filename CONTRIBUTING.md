# Contributing

Issues, disagreement and new checks are welcome.

## Adding a check

1. Put fact gathering in `recover.py` or `blutter.py`. No judgement there.
2. Put the verdict in `judge.py`. Return exactly one `Check` on every path, including the one
   where the check cannot run.
3. Add a case to `tests/test_checks.py` where it **must fire**.
4. Add a case where it **must stay silent**, built from the same input with the one fact
   changed. A clean case from a different app proves little.
5. If the check reads a symbol name, decide what happens on an obfuscated build. It may FAIL
   when it finds its target. It may not PASS.
6. If you can, add the behaviour to the twin apps in `fixtures/apps/` and the expected verdict
   to `tests/test_real_fixtures.py`.
7. Document it in `docs/CHECKS.md`: reads, fires, silent, not tested, limits.

Every finding needs evidence a reader can check, the impact in plain words, and a fix a
developer can paste.

## Style

- Plain language and short sentences in anything a user reads.
- No severity words in finding titles.
- Missing hardening is an observation, not a finding.

## Never

- Never commit an app you were given to test, or its Blutter output. `.gitignore` blocks APKs,
  but check before you push.
- Never upload someone else's app to an online scanner to build a fixture.
