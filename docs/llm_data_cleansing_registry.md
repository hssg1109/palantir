# LLM 데이터 클렌징 이력 레지스트리

**목적**: 고객사 소스코드를 LLM에 전달하여 진단한 모든 세션의 클렌징 수행 이력을 관리.  
**정책 문서**: `shared/references/llm_data_cleansing_policy.md`  
**상세 로그**: 각 행의 `로그 위치` → `state/<prefix>/llm_data_access_log.json`

---

## 사용 방법

- 진단 세션 1건(1 prefix) 완료 → Phase C 클렌징 수행 후 아래 표에 행 1개 추가
- `세션 종료` 열: 운영자가 새 Claude 세션 시작 후 ✅ 로 직접 변경
- `완료` 열: 모든 항목 ✅ 확인 후 전체 클렌징 완료로 간주

---

## 클렌징 이력

| 진단일 | 고객사/프로젝트 | 레포 | Skill | LLM 접근 파일 수 | testbed 삭제 | state 감사 | gitleaks redact | 세션 종료 | 완료 | 로그 위치 |
|:---:|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|---|
| (예시) 2026-04-30 | OCB / OCBWEBVIEW | ocb-community-api | injection | 5 | ✅ | ✅ | ✅ | ☐ | ☐ | state/ocb-community-api_20260430_1400/llm_data_access_log.json |
| 2026-06-23 | OCB / OCBSUGAR | ocb-gpb | all (injection/xss/file/data) | 0 | ✅ | ✅ | ✅ | ☐ | ☐ | state/ocb-gpb/llm_data_access_log.json |
| 2026-06-17 | OCB / OCBSUGAR | bms_admin | all (injection/xss/file/data) | 6 | ✅ | ✅ | ✅ | ☐ | ☐ | state/bms_admin/llm_data_access_log.json |
| 2026-06-23 | OCB / OCBSUGAR | fail-info | all (injection/xss/file/data) | 0 | ✅ | ✅ | ✅ | ☐ | ☐ | state/fail-info/llm_data_access_log.json |
| 2026-06-03 | OCB / OCBSUGAR | ocb_passbook_enc | all (injection/xss/file/data) | 5 | ✅ | ✅ | ✅ | ☐ | ☐ | state/ocb_passbook_enc/llm_data_access_log.json |
| 2026-06-25 | OCB / OCBSUGAR | trwas | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/trwas/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocb-admin-frontend | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-admin-frontend/llm_data_access_log.json |
| 2026-06-15 | OCB / OCBSUGAR | ocb-bridge-scheduler | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-bridge-scheduler/llm_data_access_log.json |
| 2026-06-30 | OCB / OCBWEBVIEW | ocb-community-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-community-api/llm_data_access_log.json |
| 2026-06-30 | OCB / OCBWEBVIEW | ocb-community-ssr | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-community-ssr/llm_data_access_log.json |
| 2026-06-15 | OCB / OCBSUGAR | ocb-deep-link | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-deep-link/llm_data_access_log.json |
| 2026-06-01 | OCB / OCBSUGAR | ocb-epm | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-epm/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocb-fnc-webview-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-fnc-webview-api/llm_data_access_log.json |
| 2026-06-01 | OCB / OCBSUGAR | ocb-iam | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-iam/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocb-joy-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-joy-api/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocb-joy-frontend | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-joy-frontend/llm_data_access_log.json |
| 2026-06-25 | OCB / OCBSUGAR | ocb-nrn | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-nrn/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocb-nxmile-mq-worker | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-nxmile-mq-worker/llm_data_access_log.json |
| 2026-06-30 | OCB / OCBWEBVIEW | ocb-ogeul-admin-frontend | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-ogeul-admin-frontend/llm_data_access_log.json |
| 2026-06-15 | OCB / OCBSUGAR | ocb-soi-appweb | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-soi-appweb/llm_data_access_log.json |
| 2026-06-30 | OCB / OCBWEBVIEW | ocb-webview-admin-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-webview-admin-api/llm_data_access_log.json |
| 2026-06-23 | OCB / OCBWEBVIEW | ocb-webview-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-webview-api/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocb-webview-batch | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-webview-batch/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocb-webview-deeplink | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-webview-deeplink/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocb-webview-frontend | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-webview-frontend/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocb-webview-nxmile-grpc | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-webview-nxmile-grpc/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocb-webview-reward-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-webview-reward-api/llm_data_access_log.json |
| 2026-06-01 | OCB / OCBSUGAR | ocb-wp-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-wp-api/llm_data_access_log.json |
| 2026-06-24 | OCB / OCBSUGAR | ocb-wp-frontend | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocb-wp-frontend/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocbws-frontend | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocbws-frontend/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocbws-nxmile-gateway | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocbws-nxmile-gateway/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBWEBVIEW | ocbws-web-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocbws-web-api/llm_data_access_log.json |
| 2026-05-21 | OCB / OCBWEBVIEW | ocbws-web-ui | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/ocbws-web-ui/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBSUGAR | soi-event-consumer | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/soi-event-consumer/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBSUGAR | sugar-admin-worker | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/sugar-admin-worker/llm_data_access_log.json |
| 2026-06-16 | OCB / OCBSUGAR | sugar-kafka | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/sugar-kafka/llm_data_access_log.json |
| 2026-06-17 | OCB / LIVECM | main-api-kt | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | 🔲 | 🔲 | state/main-api-kt/llm_data_access_log.json |
| 2026-06-23 | OCB / LIVECM | admin-api-py | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | 🔲 | 🔲 | state/admin-api-py/llm_data_access_log.json |
| 2026-07-13 | OCB / LIVECM | main-api-on-lambda-kt | all (injection/xss/file/data/sca) | - | ✅ | ✅ | ✅ | 🔲 | 🔲 | state/main-api-on-lambda-kt/llm_data_access_log.json |
| 2026-06-17 | OCB / LIVECM | admin-api-kt | all (injection/xss/file/data/sca) | - | ✅ | ✅ | ✅ | ✅ | ✅ | state/admin-api-kt/llm_data_access_log.json |
| 2026-06-22 | OCB / LIVECM | external-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | 🔲 | 🔲 | state/external-api/llm_data_access_log.json |
| 2026-06-22 | OCB / LIVECM | websocket-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | 🔲 | 🔲 | state/websocket-api/llm_data_access_log.json |
| 2026-06-22 | OCB / LIVECM | batch-api | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | 🔲 | 🔲 | state/batch-api/llm_data_access_log.json |
| 2026-06-29 | OCB / LIVECM | thirdparty-api-kt | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | 🔲 | 🔲 | state/thirdparty-api-kt/llm_data_access_log.json |
| 2026-06-29 | OCB / LIVECM | batch-script | all (injection / xss / file / data / sca) | - | ✅ | ✅ | ✅ | 🔲 | 🔲 | state/batch-script/llm_data_access_log.json |
| 2026-06-24 | OCB / LIVECM | live-commerce-backend | all (injection/xss/file/data) | 0 | ✅ | ✅ | ✅ | ☐ | ☐ | state/live-commerce-backend/llm_data_access_log.json |
| 2026-06-25 | OCB / LIVECM | live-frontend | all (injection/xss/file/data) | 10 | ✅ | ✅ | ✅ | ☐ | ☐ | state/live-frontend/llm_data_access_log.json |
| 2026-06-25 | OCB / LIVECM | live-frontend-nextjs | all (xss/file/data) | 13 | ✅ | ✅ | ✅ | ☐ | ☐ | state/live-frontend-nextjs/llm_data_access_log.json |

<!-- 실제 이력은 위 예시 행 아래에 추가 -->

---

## 열 설명

| 열 | 설명 |
|---|---|
| **진단일** | 진단 시작일 (YYYY-MM-DD) |
| **고객사/프로젝트** | 고객사명 / Bitbucket 프로젝트 키 |
| **레포** | 진단 대상 레포 이름 |
| **Skill** | 실행한 skill (injection / xss / file / data / sca) |
| **LLM 접근 파일 수** | Phase 1 + Phase 3에서 LLM이 Read한 파일 총 수 |
| **testbed 삭제** | `testbed/<repo>/` 로컬 삭제 완료 여부 |
| **state 감사** | state/ 내 원본 소스코드 파일 잔류 없음 확인 여부 |
| **gitleaks redact** | seed_gitleaks.json `--redact` 적용 확인 여부 (미실행 시 N/A) |
| **세션 종료** | 운영자가 LLM 세션 종료 (새 세션 시작) 완료 여부 |
| **완료** | 모든 항목 ✅ 시 완료 표시 |
| **로그 위치** | `state/<prefix>/llm_data_access_log.json` 경로 |

---

## 미완료 항목 처리

- `세션 종료` ☐ 상태인 행이 있으면 운영자가 해당 세션 종료 후 ✅ 업데이트
- 클렌징 불가 사유 발생 시 로그(`llm_data_access_log.json`)의 `notes` 필드에 사유 기록 후 이 표의 `완료` 열에 ⚠️ 표시
