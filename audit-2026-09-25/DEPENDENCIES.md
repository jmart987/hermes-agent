# Dependency findings

OSV observation: 2026-09-25T17:55:52.960019+00:00. 2800 distinct registry package/version tuples assessed. 21 match at least one advisory; 50 advisory identifiers before alias deduplication. Zero failed batches or truncated result pages.

The raw query includes one excluded editable project record (`hermes-agent==0.0.0`): that placeholder is not the audited Git commit/version and its matches are not dependency findings. All lockfile versions, optional dependencies and development dependencies are included. This is not an inventory of installed packages or a reachability test. No private environment or installed plugin/MCP configuration was read.

| Package | Lock evidence / scope | Advisory and severity | Fixed versions reported for this package |
|---|---|---|---|
| PyPI `httpcore2==2.7.0` | `uv.lock:2865` (optional/platform superset) | [GHSA-7mj9-2mp8-4m2p](https://osv.dev/vulnerability/GHSA-7mj9-2mp8-4m2p) — HIGH | 2.10.0 |
| PyPI `httpcore2==2.7.0` | `uv.lock:2865` (optional/platform superset) | [PYSEC-2026-3844](https://osv.dev/vulnerability/PYSEC-2026-3844) — not supplied | 2.10.0 |
| PyPI `httpx2==2.7.0` | `uv.lock:2369` (optional/platform superset) | [GHSA-7mj9-2mp8-4m2p](https://osv.dev/vulnerability/GHSA-7mj9-2mp8-4m2p) — HIGH | 2.10.0 |
| PyPI `httpx2==2.7.0` | `uv.lock:2369` (optional/platform superset) | [GHSA-8xx6-hgc6-gc2m](https://osv.dev/vulnerability/GHSA-8xx6-hgc6-gc2m) — HIGH | 2.12.0 |
| PyPI `httpx2==2.7.0` | `uv.lock:2369` (optional/platform superset) | [GHSA-f2fp-rgf2-35cp](https://osv.dev/vulnerability/GHSA-f2fp-rgf2-35cp) — MODERATE | 2.10.0 |
| PyPI `httpx2==2.7.0` | `uv.lock:2369` (optional/platform superset) | [GHSA-h4x7-gw46-3wm6](https://osv.dev/vulnerability/GHSA-h4x7-gw46-3wm6) — MODERATE | 2.11.0 |
| PyPI `httpx2==2.7.0` | `uv.lock:2369` (optional/platform superset) | [GHSA-pf96-p4fj-6566](https://osv.dev/vulnerability/GHSA-pf96-p4fj-6566) — MODERATE | 2.11.0 |
| PyPI `httpx2==2.7.0` | `uv.lock:2369` (optional/platform superset) | [PYSEC-2026-3845](https://osv.dev/vulnerability/PYSEC-2026-3845) — not supplied | 2.10.0 |
| PyPI `httpx2==2.7.0` | `uv.lock:2369` (optional/platform superset) | [PYSEC-2026-3846](https://osv.dev/vulnerability/PYSEC-2026-3846) — not supplied | 2.12.0 |
| PyPI `httpx2==2.7.0` | `uv.lock:2369` (optional/platform superset) | [PYSEC-2026-3847](https://osv.dev/vulnerability/PYSEC-2026-3847) — not supplied | 2.10.0 |
| PyPI `httpx2==2.7.0` | `uv.lock:2369` (optional/platform superset) | [PYSEC-2026-3848](https://osv.dev/vulnerability/PYSEC-2026-3848) — not supplied | 2.11.0 |
| PyPI `httpx2==2.7.0` | `uv.lock:2369` (optional/platform superset) | [PYSEC-2026-3849](https://osv.dev/vulnerability/PYSEC-2026-3849) — not supplied | 2.11.0 |
| npm `@vitest/mocker==4.1.10` | `package-lock.json:7052` (dev/build) | [GHSA-82fw-gwwq-j7x9](https://osv.dev/vulnerability/GHSA-82fw-gwwq-j7x9) — MODERATE | 4.1.11, 5.0.0-rc.2 |
| npm `@xmldom/xmldom==0.8.13` | `package-lock.json:7153` (dev/build) | [GHSA-27p8-2357-5qqv](https://osv.dev/vulnerability/GHSA-27p8-2357-5qqv) — HIGH | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.8.13` | `package-lock.json:7153` (dev/build) | [GHSA-4w3w-2rp5-g8jm](https://osv.dev/vulnerability/GHSA-4w3w-2rp5-g8jm) — HIGH | 0.8.14, 0.9.11 |
| npm `@xmldom/xmldom==0.8.13` | `package-lock.json:7153` (dev/build) | [GHSA-6gmq-8vp8-gcm6](https://osv.dev/vulnerability/GHSA-6gmq-8vp8-gcm6) — MODERATE | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.8.13` | `package-lock.json:7153` (dev/build) | [GHSA-6h8r-xr42-gp59](https://osv.dev/vulnerability/GHSA-6h8r-xr42-gp59) — MODERATE | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.8.13` | `package-lock.json:7153` (dev/build) | [GHSA-8344-3jmq-59r6](https://osv.dev/vulnerability/GHSA-8344-3jmq-59r6) — HIGH | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.8.13` | `package-lock.json:7153` (dev/build) | [GHSA-93r5-fhx6-vmg9](https://osv.dev/vulnerability/GHSA-93r5-fhx6-vmg9) — HIGH | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.8.13` | `package-lock.json:7153` (dev/build) | [GHSA-965w-775f-mr7g](https://osv.dev/vulnerability/GHSA-965w-775f-mr7g) — HIGH | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.8.13` | `package-lock.json:7153` (dev/build) | [GHSA-c7q8-3ch8-vqpv](https://osv.dev/vulnerability/GHSA-c7q8-3ch8-vqpv) — HIGH | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.8.13` | `package-lock.json:7153` (dev/build) | [GHSA-w2rr-34g9-rvrj](https://osv.dev/vulnerability/GHSA-w2rr-34g9-rvrj) — HIGH | 0.8.14, 0.9.11 |
| npm `@xmldom/xmldom==0.8.13` | `package-lock.json:7153` (dev/build) | [GHSA-x4fp-j954-r2f4](https://osv.dev/vulnerability/GHSA-x4fp-j954-r2f4) — HIGH | 0.8.15 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-27p8-2357-5qqv](https://osv.dev/vulnerability/GHSA-27p8-2357-5qqv) — HIGH | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-3px3-54cx-rmw9](https://osv.dev/vulnerability/GHSA-3px3-54cx-rmw9) — HIGH | 0.9.12 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-4w3w-2rp5-g8jm](https://osv.dev/vulnerability/GHSA-4w3w-2rp5-g8jm) — HIGH | 0.8.14, 0.9.11 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-6gmq-8vp8-gcm6](https://osv.dev/vulnerability/GHSA-6gmq-8vp8-gcm6) — MODERATE | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-6h8r-xr42-gp59](https://osv.dev/vulnerability/GHSA-6h8r-xr42-gp59) — MODERATE | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-6mj3-qw4j-hgrw](https://osv.dev/vulnerability/GHSA-6mj3-qw4j-hgrw) — HIGH | 0.9.12 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-8344-3jmq-59r6](https://osv.dev/vulnerability/GHSA-8344-3jmq-59r6) — HIGH | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-93r5-fhx6-vmg9](https://osv.dev/vulnerability/GHSA-93r5-fhx6-vmg9) — HIGH | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-965w-775f-mr7g](https://osv.dev/vulnerability/GHSA-965w-775f-mr7g) — HIGH | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-c7q8-3ch8-vqpv](https://osv.dev/vulnerability/GHSA-c7q8-3ch8-vqpv) — HIGH | 0.8.15, 0.9.12 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-g53g-w8rj-fmg7](https://osv.dev/vulnerability/GHSA-g53g-w8rj-fmg7) — HIGH | 0.9.11 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-vr34-hp96-76pp](https://osv.dev/vulnerability/GHSA-vr34-hp96-76pp) — HIGH | 0.9.12 |
| npm `@xmldom/xmldom==0.9.10` | `package-lock.json:19292` (dev/build) | [GHSA-w2rr-34g9-rvrj](https://osv.dev/vulnerability/GHSA-w2rr-34g9-rvrj) — HIGH | 0.8.14, 0.9.11 |
| npm `baseline-browser-mapping==2.10.43` | `website/package-lock.json:6641` (runtime or mixed) | [GHSA-w5vr-8v7q-w6rv](https://osv.dev/vulnerability/GHSA-w5vr-8v7q-w6rv) — MODERATE | 2.11.0 |
| npm `browserslist==4.28.6` | `website/package-lock.json:6802` (runtime or mixed) | [GHSA-73wf-gq98-2v4g](https://osv.dev/vulnerability/GHSA-73wf-gq98-2v4g) — HIGH | 4.28.7 |
| npm `browserslist==4.28.6` | `website/package-lock.json:6802` (runtime or mixed) | [GHSA-c83g-rgw3-j3cx](https://osv.dev/vulnerability/GHSA-c83g-rgw3-j3cx) — HIGH | 4.28.7 |
| npm `colord==2.9.3` | `website/package-lock.json:7300` (runtime or mixed) | [GHSA-2wm5-q62r-hmrv](https://osv.dev/vulnerability/GHSA-2wm5-q62r-hmrv) — MODERATE | 2.9.4 |
| npm `diff==7.0.0` | `nix/node-gyp-11-4-0-package-lock.json:1362` (dev/build) | [GHSA-73rr-hh4g-fpgx](https://osv.dev/vulnerability/GHSA-73rr-hh4g-fpgx) — LOW | 3.5.1, 4.0.4, 5.2.2, 8.0.3 |
| npm `electron==40.10.2` | `package-lock.json:480` (dev/build) | [GHSA-9f4c-93c8-jc8g](https://osv.dev/vulnerability/GHSA-9f4c-93c8-jc8g) — HIGH | 39.8.10, 41.10.3, 42.0.1 |
| npm `electron==40.10.2` | `package-lock.json:480` (dev/build) | [GHSA-r4w5-6pfg-jxp5](https://osv.dev/vulnerability/GHSA-r4w5-6pfg-jxp5) — MODERATE | 40.10.6, 41.9.1, 42.5.1, 43.0.0 |
| npm `extract-zip==2.0.1` | `package-lock.json:10751` (dev/build) | [GHSA-7pqw-9j4j-h8q3](https://osv.dev/vulnerability/GHSA-7pqw-9j4j-h8q3) — HIGH | No fixed range supplied |
| npm `extract-zip==2.0.1` | `package-lock.json:10751` (dev/build) | [GHSA-jmr9-qjv8-65gv](https://osv.dev/vulnerability/GHSA-jmr9-qjv8-65gv) — HIGH | No fixed range supplied |
| npm `fast-uri==3.1.5` | `website/package-lock.json:9577` (runtime or mixed) | [GHSA-5jgf-p345-68v8](https://osv.dev/vulnerability/GHSA-5jgf-p345-68v8) — HIGH | 2.4.5, 3.1.6, 4.1.3 |
| npm `fast-uri==3.1.5` | `website/package-lock.json:9577` (runtime or mixed) | [GHSA-f65p-4m7j-42xc](https://osv.dev/vulnerability/GHSA-f65p-4m7j-42xc) — HIGH | 2.4.5, 3.1.6, 4.1.3 |
| npm `fast-uri==3.1.5` | `website/package-lock.json:9577` (runtime or mixed) | [GHSA-fph4-wmhf-6fwf](https://osv.dev/vulnerability/GHSA-fph4-wmhf-6fwf) — HIGH | 2.4.5, 3.1.6, 4.1.3 |
| npm `fast-uri==3.1.5` | `website/package-lock.json:9577` (runtime or mixed) | [GHSA-jqff-g426-hqxp](https://osv.dev/vulnerability/GHSA-jqff-g426-hqxp) — HIGH | 2.4.5, 3.1.6, 4.1.3 |
| npm `joi==17.13.4` | `website/package-lock.json:11206` (runtime or mixed) | [GHSA-6w3j-5fw6-r9vr](https://osv.dev/vulnerability/GHSA-6w3j-5fw6-r9vr) — LOW | 17.13.6, 18.2.5 |
| npm `joi==17.13.4` | `website/package-lock.json:11206` (runtime or mixed) | [GHSA-gg4h-3hg2-grpc](https://osv.dev/vulnerability/GHSA-gg4h-3hg2-grpc) — LOW | 17.13.5, 18.2.4 |
| npm `joi==18.2.3` | `package-lock.json:12647` (dev/build) | [GHSA-6w3j-5fw6-r9vr](https://osv.dev/vulnerability/GHSA-6w3j-5fw6-r9vr) — LOW | 17.13.6, 18.2.5 |
| npm `joi==18.2.3` | `package-lock.json:12647` (dev/build) | [GHSA-gg4h-3hg2-grpc](https://osv.dev/vulnerability/GHSA-gg4h-3hg2-grpc) — LOW | 17.13.5, 18.2.4 |
| npm `js-yaml==4.3.1` | `nix/node-gyp-11-4-0-package-lock.json:3076` (dev/build); `package-lock.json:12672` (runtime or mixed); `website/package-lock.json:11225` (runtime or mixed) | [GHSA-2883-xcg3-v3hh](https://osv.dev/vulnerability/GHSA-2883-xcg3-v3hh) — HIGH | 3.15.2, 4.3.2 |
| npm `nanoid==3.3.17` | `website/package-lock.json:16238` (runtime or mixed) | [GHSA-2v37-7h3g-55p8](https://osv.dev/vulnerability/GHSA-2v37-7h3g-55p8) — HIGH | 3.3.18, 5.1.6 |
| npm `qs==6.15.3` | `website/package-lock.json:16407` (runtime or mixed) | [GHSA-4mjr-xmp4-gh2g](https://osv.dev/vulnerability/GHSA-4mjr-xmp4-gh2g) — MODERATE | 6.16.0 |
| npm `qs==6.15.3` | `website/package-lock.json:16407` (runtime or mixed) | [GHSA-x5fp-wj9c-mxmx](https://osv.dev/vulnerability/GHSA-x5fp-wj9c-mxmx) — MODERATE | 6.16.0 |
| npm `serialize-javascript==6.0.2` | `nix/node-gyp-11-4-0-package-lock.json:4183` (dev/build) | [GHSA-5c6j-r48x-rmvq](https://osv.dev/vulnerability/GHSA-5c6j-r48x-rmvq) — HIGH | 7.0.3 |
| npm `serialize-javascript==6.0.2` | `nix/node-gyp-11-4-0-package-lock.json:4183` (dev/build) | [GHSA-qj8w-gfj5-8c6v](https://osv.dev/vulnerability/GHSA-qj8w-gfj5-8c6v) — MODERATE | 7.0.5 |
| npm `svgo==3.3.4` | `website/package-lock.json:18157` (runtime or mixed) | [GHSA-4vpr-x523-8j87](https://osv.dev/vulnerability/GHSA-4vpr-x523-8j87) — MODERATE | 2.8.4, 3.3.5, 4.1.0 |
| npm `svgo==3.3.4` | `website/package-lock.json:18157` (runtime or mixed) | [GHSA-w27v-7q3p-w38r](https://osv.dev/vulnerability/GHSA-w27v-7q3p-w38r) — HIGH | 2.8.4, 3.3.5, 4.1.0 |
| npm `vitest==4.1.10` | `package-lock.json:18574` (dev/build) | [GHSA-82fw-gwwq-j7x9](https://osv.dev/vulnerability/GHSA-82fw-gwwq-j7x9) — MODERATE | 4.1.11, 5.0.0-rc.2 |
| npm `yaml==2.8.1` | `package-lock.json:19122` (runtime or mixed) | [GHSA-48c2-rrv3-qjmp](https://osv.dev/vulnerability/GHSA-48c2-rrv3-qjmp) — MODERATE | 1.10.3, 2.8.3 |
