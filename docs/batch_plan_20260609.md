# 저녁 배치 실행 계획 — 2026-06-09

## 현황 요약

### 완료된 레포 (이번 세션 처리)
- **fail-info** — 전 스킬 해당없음 (정적 HTML, Ant build)
- **ocb-gpb** — 전 스킬 해당없음 (Protobuf IDL only)
- **ocb-wp-frontend** — injection/file/data 해당없음, xss 정보 1건, sca 취약 5건(axios)

---

## 배치 대상 레포 (25 skill 실행)

### A. 6개 레포 — xss/file/data/sca 4종 실행 필요

> injection은 완료(0건). xss/file/data/sca run dir만 있고 실제 scan 파일 없음 → 4개 skill 신규 실행.

| 레포 | injection | xss | file | data | sca |
|---|---|---|---|---|---|
| soi-event-consumer | ✅ | ❌ | ❌ | ❌ | ❌ |
| sugar-admin-worker | ✅ | ❌ | ❌ | ❌ | ❌ |
| sugar-kafka | ✅ | ❌ | ❌ | ❌ | ❌ |
| ocb-bridge-scheduler | ✅ | ❌ | ❌ | ❌ | ❌ |
| ocb-deep-link | ✅ | ❌ | ❌ | ❌ | ❌ |
| ocb-soi-appweb | ✅ | ❌ | ❌ | ❌ | ❌ |

**실행 skill 수**: 6레포 × 4스킬 = **24건**

### B. bms_admin — injection + sca LLM-Check 필요

| 스킬 | 상태 | 필요 작업 |
|---|---|---|
| injection | 🔄 api_scan.json만 존재 (LLM-Check 미실행) | `/sec-scan-injection bms_admin` 재실행 |
| xss | ✅ findings=3 | — |
| file | ✅ findings=0 | — |
| data | ✅ findings=3 | — |
| sca | 🔄 llm_checked=None | sca LLM-Check 실행 |

**실행 skill 수**: **2건** (injection 재실행, sca LLM-Check)

---

## 실행 순서 (총 26건)

### Phase 1 — 6개 레포 배치 (레포 단위로 순차 실행)

```
# soi-event-consumer
/sec-scan-xss soi-event-consumer
/sec-scan-file soi-event-consumer
/sec-scan-data soi-event-consumer
/sec-scan-sca soi-event-consumer

# sugar-admin-worker
/sec-scan-xss sugar-admin-worker
/sec-scan-file sugar-admin-worker
/sec-scan-data sugar-admin-worker
/sec-scan-sca sugar-admin-worker

# sugar-kafka
/sec-scan-xss sugar-kafka
/sec-scan-file sugar-kafka
/sec-scan-data sugar-kafka
/sec-scan-sca sugar-kafka

# ocb-bridge-scheduler
/sec-scan-xss ocb-bridge-scheduler
/sec-scan-file ocb-bridge-scheduler
/sec-scan-data ocb-bridge-scheduler
/sec-scan-sca ocb-bridge-scheduler

# ocb-deep-link
/sec-scan-xss ocb-deep-link
/sec-scan-file ocb-deep-link
/sec-scan-data ocb-deep-link
/sec-scan-sca ocb-deep-link

# ocb-soi-appweb
/sec-scan-xss ocb-soi-appweb
/sec-scan-file ocb-soi-appweb
/sec-scan-data ocb-soi-appweb
/sec-scan-sca ocb-soi-appweb
```

### Phase 2 — bms_admin 마무리

```
/sec-scan-injection bms_admin
# bms_admin sca LLM-Check (api_scan.json → LLM review → findings_sca.json)
```

### Phase 3 — 리뷰 & 보고서 (Phase 1+2 완료 후)

```bash
# 각 레포 리뷰
/sec-review <RUN_ID> soi-event-consumer
/sec-review <RUN_ID> sugar-admin-worker
/sec-review <RUN_ID> sugar-kafka
/sec-review <RUN_ID> ocb-bridge-scheduler
/sec-review <RUN_ID> ocb-deep-link
/sec-review <RUN_ID> ocb-soi-appweb
/sec-review <RUN_ID> bms_admin

# 보고서 생성 + Confluence 게시
python3 tools/approve_report.py --run-id <RUN_ID> --repo soi-event-consumer --publish
python3 tools/approve_report.py --run-id <RUN_ID> --repo sugar-admin-worker --publish
python3 tools/approve_report.py --run-id <RUN_ID> --repo sugar-kafka --publish
python3 tools/approve_report.py --run-id <RUN_ID> --repo ocb-bridge-scheduler --publish
python3 tools/approve_report.py --run-id <RUN_ID> --repo ocb-deep-link --publish
python3 tools/approve_report.py --run-id <RUN_ID> --repo ocb-soi-appweb --publish
python3 tools/approve_report.py --run-id <RUN_ID> --repo bms_admin --publish
```

---

## 참고 — 레포 특성 메모

| 레포 | 언어/프레임워크 | 예상 특이사항 |
|---|---|---|
| soi-event-consumer | Kotlin/Spring (이벤트 컨슈머) | Kafka 메시지 처리. XSS/파일 해당없음 가능 |
| sugar-admin-worker | Kotlin/Spring (배치 워커) | 관리자 배치 작업. XSS 해당없음 가능 |
| sugar-kafka | Kotlin (Kafka 라이브러리) | Kafka 공통 유틸. XSS/파일 해당없음 가능 |
| ocb-bridge-scheduler | Kotlin/Spring (스케줄러) | 스케줄 작업. XSS 해당없음 가능 |
| ocb-deep-link | Kotlin/Spring (딥링크) | URL 처리 → Redirect XSS 주의 |
| ocb-soi-appweb | Java Spring Web | 웹 앱 → XSS/파일 취약점 가능성 있음 |
| bms_admin | Java Spring (어드민) | XSS 3건·data 3건 이미 발견. injection 재확인 |
