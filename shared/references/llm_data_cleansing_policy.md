# LLM 데이터 클렌징 정책

**버전**: 1.0  
**최초 작성**: 2026-04-30  
**적용 범위**: palantir 전체 skill (sec-scan-injection / xss / file / data / sca)

---

## 1. 배경 및 목적

palantir의 진단 워크플로는 **Phase 3 LLM-Check** 단계에서 Claude(LLM)가 고객사 소스코드를 직접 읽어 취약점 교차검증을 수행한다. 이 과정에서 고객사 소스코드 일부가 **Anthropic API 서버로 전송**된다.

이 정책은 다음을 목적으로 한다:
- 진단 완료 후 고객사 소스코드의 잔류를 최소화하는 클렌징 절차 정의
- 각 진단 세션에서 LLM이 접근한 파일 목록과 클렌징 수행 여부를 기록·관리

---

## 2. LLM에 전송되는 데이터 — Phase별 분류

| Phase | LLM 전송 여부 | 전송 데이터 |
|---|:---:|---|
| **Phase 1** 자산 식별 | **전송됨** | 디렉토리 구조, `build.gradle` / `settings.gradle` / `application.yml` 등 빌드·설정 파일 내용, Git 메타데이터 (commit hash, 담당자명, 이메일, remote URL) |
| **Phase 2** 자동 스캔 | **미전송** | Python 스크립트 로컬 실행 — 결과 JSON만 `state/` 에 저장. 소스코드 자체는 LLM 미전송 |
| **Phase 3** LLM-Check | **전송됨** | Controller / Service / Repository / DAO 소스코드, MyBatis XML SQL, DTO 클래스, 취약 의심 코드 스니펫 |

> **참고 — Anthropic 데이터 처리**  
> - `claude-cli` (Claude Pro 구독) 사용 시: 대화 내용이 Anthropic 서버에 보관되며 서비스 개선 목적으로 활용될 수 있음. 필요 시 Anthropic 계정 설정에서 "대화 데이터 훈련 사용" 옵션을 해제할 것.  
> - Anthropic API (유료 API Key) 사용 시: 기본적으로 입력 데이터를 훈련에 사용하지 않으며, 30일 후 삭제됨 (Anthropic Privacy Policy 기준).  
> - 고객사 소스코드 처리에 대한 Anthropic 서버 측 삭제는 palantir가 직접 제어할 수 없으며, 클라이언트 측 클렌징(아래 Section 3)을 통해 최소화한다.

---

## 3. 클렌징 요건 — 진단 완료 후 필수 수행

### 3-1. testbed 삭제 (로컬 클렌징)

```bash
rm -rf testbed/<repo>/
```

- `/sec-review` 완료 직후 Claude가 자동 수행 (Phase C-2)
- **각 skill 완료 시 삭제하지 않는다** — 이후 skill 진단에 testbed가 필요하기 때문
- 5개 skill 모두 완료 후 `/sec-review` 시점에 1회 삭제

### 3-2. LLM 세션 종료 (컨텍스트 클렌징)

- 진단 세션 종료 후 **새 Claude 세션을 시작** — 고객사 소스코드가 포함된 대화 컨텍스트가 활성 세션에 잔류하지 않도록 함
- 동일 세션에서 다른 고객사 진단을 이어서 진행하지 말 것

### 3-3. state/ 파일 내 소스코드 잔류 방지

- `state/<prefix>/` 에는 **취약점 스니펫 (findings의 `code_snippet`, `taint_evidence`)** 만 허용
- 고객사 소스코드 파일 전체 내용을 state/에 복사·저장하는 것은 금지
- `scan_data_protection.py`의 내장 `_redact_snippet()` 함수가 code_snippet 생성 시 자동으로 자격증명 값을 마스킹(`[REDACTED]`)하므로 별도 외부 도구 실행 불필요

---

## 4. 클렌징 기록 — llm_data_access_log.json

각 skill Phase C-1 단계에서 `state/<repo>/llm_data_access_log.json` (레포당 1개 통합 파일)에 해당 skill의 LLM 접근 파일 목록을 기록하고, `/sec-review` Phase C-2 완료 시 클렌징 액션 결과와 Confluence 레지스트리 행 추가를 수행한다.

- **로그 위치**: `state/<repo>/llm_data_access_log.json` (레포당 1파일, 5 skill 통합)
- **Confluence 레지스트리**: pageId `<YOUR_REGISTRY_PAGE_ID>` — 레포당 1행 추가
- 스키마 정의: `shared/references/output_schemas.md` → `llm_data_access_log.json Schema` 섹션 참조.
- 절차 상세: `shared/references/phase_c_cleansing.md` 참조.

---

## 5. 책임

| 역할 | 책임 |
|---|---|
| **진단 수행자 (Claude)** | 진단 완료 후 자동으로 `llm_data_access_log.json` 생성 및 testbed 삭제 수행 |
| **운영자 (사람)** | 세션 종료 확인, `docs/llm_data_cleansing_registry.md` 레지스트리 최종 검토·서명 |
| **감사자** | 레지스트리 및 개별 로그(`llm_data_access_log.json`)를 통한 이행 여부 확인 |

---

## 6. 클렌징 체크리스트 (Phase C 완료 기준)

레포 1건 완료 시 아래 항목을 모두 확인해야 Phase C가 완료된 것으로 간주한다.

**C-1 (각 skill 완료 시, 5회)**
- [ ] `state/<repo>/llm_data_access_log.json` — 해당 skill 항목 append 완료

**C-2 (/sec-review 완료 시, 1회)**
- [ ] `testbed/<repo>/` 삭제 완료
- [ ] state/ 내 소스코드 전체 파일 복사 없음 확인
- [ ] `scan_data_protection.py` 스캔 redact 적용 확인 (data skill 실행 시 자동 ✅)
- [ ] Confluence 레지스트리 (pageId: `<YOUR_REGISTRY_PAGE_ID>`) 행 추가 완료
- [ ] `llm_data_access_log.json` `cleansing_completed: true` 저장 완료
- [ ] LLM 세션 종료 예정 (운영자 수행)
