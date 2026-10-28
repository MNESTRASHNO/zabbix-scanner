# research/

Raw output of the research phase: CVE/advisory/component records, version
timelines, credential lists, and deep-vector notes that were used to build the
consolidated database in `db/`.

- `*_records.json` — structured records (CVE, advisory, component, credentials,
  pocs, versions); input for `scripts/build_db.py`.
- `*_notes.md` — sources, reasoning, audit trails, deep-dive writeups.
- `tmp/` and `old_versions_lab/` — scratch files and ad-hoc Dockerfiles for
  versions not on Docker Hub (not committed).

`scripts/build_db.py` reads these artifacts and reproduces `db/*.json`.