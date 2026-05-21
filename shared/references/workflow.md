# Audit Workflow Definition

## 자율 완주 원칙 (CRITICAL)

> 실행 중 Claude는 **절대 확인 질문을 하지 않는다.**
>
> - "진행할까요?", "계속할까요?", "do you want to proceed?" 등 일체 금지.
> - Phase 1 → 2 → 3을 사용자 개입 없이 끝까지 완주한다.
> - 스크립트 실패, 빌드 오류, 파일 없음 → fallback 자동 적용 후 다음 단계 진행.
> - **유일한 예외**: 토큰/자격증명 누락 등 인간만 해결 가능한 blocking 오류 시 보고 후 대기.

## Phase 구조

```
Phase 1: 자산 식별
  └─ Task 1-1: 자산 목록 작성
       ├─ ⚠️ 프론트엔드 판정 [Phase 1에서 반드시 확정]:
       │   조건: package.json 존재 AND .java/.kt 파일 0건
       │   해당 시: 자산 식별 결과에 repo_type = "frontend" 기록
       │   → Phase 2에서 백엔드 스캔(injection/xss/file/data) skip, 프론트엔드 진단 실행
       └─ nginx-only repo(소스 없음): Phase 2 전량 skip, 결과에 "해당없음" 기록

Phase 2: 정적 분석 (자동스캔)
  ├─ [백엔드 Java/Kotlin repo]
  │  ├─ Task 2-1: API 인벤토리 추출 (선행)
  │  │   python3 shared/scripts/scan_api.py <src> -o state/<prefix>/api_scan.json
  │  ├─ 병렬 실행 (2-1 완료 후):
  │  │  ├─ Injection: shared/scripts/scan_injection_enhanced.py
  │  │  ├─ XSS:       shared/scripts/scan_xss.py
  │  │  ├─ File처리:  shared/scripts/scan_file_processing.py
  │  │  └─ 데이터보호: shared/scripts/scan_data_protection.py
  │  └─ ⚠️ SCA 진단 [항상 필수]: shared/scripts/scan_sca_gradle_tree.py
  │
  └─ [프론트엔드 JS/TS repo] — 백엔드 스캔 전량 skip
     ├─ FE-XSS: dangerouslySetInnerHTML / innerHTML / eval() / document.write()
     ├─ FE-SECRET: .env 커밋 / 소스 내 API 키 하드코딩
     ├─ FE-STORAGE: localStorage/sessionStorage 민감 데이터
     ├─ FE-LOG: console.log PII 포함
     └─ ⚠️ SCA 진단 [항상 필수]: shared/scripts/scan_sca_gradle_tree.py

Phase 3: LLM-Check (자동스캔 결과 교차검증 + 수동 심층진단)
  ├─ [백엔드] 인젝션 교차검증     → task22_llm.json
  ├─ [백엔드] XSS 교차검증        → task23_llm.json
  ├─ [백엔드] 파일처리 교차검증   → task24_llm.json
  ├─ [백엔드] 데이터보호 교차검증 → task25_llm.json
  └─ SCA LLM 검토                 → sca_llm.json

Phase C: LLM 데이터 클렌징 ⚠️ 필수 — Phase 3 완료 후, Phase 4 이전
  ├─ llm_data_access_log.json 생성 (Phase 1~3 LLM 접근 파일 목록 + 클렌징 기록)
  │   → state/<prefix>/llm_data_access_log.json
  ├─ testbed/<repo>/ 삭제 확인
  ├─ state/ 내 원본 소스코드 파일 복사 없음 확인 (findings 스니펫만 허용)
  ├─ seed_gitleaks.json 존재 시 --redact 적용 여부 확인
  ├─ docs/llm_data_cleansing_registry.md 레지스트리 행 추가
  └─ [운영자] Claude 세션 종료 → 새 세션 시작 (컨텍스트 만료)
```

> **정책 문서**: `shared/references/llm_data_cleansing_policy.md`  
> **Phase 4(보고서 생성/Confluence 게시) + Phase 5(SSC 정합성 검증)** 절차는 **sec-audit-playbook** 레포 참조.

## Task별 프롬프트

각 태스크의 상세 진단 기준 및 실행 지침:
- `shared/references/task_prompts/task_11_asset_identification.md`
- `sec-scan-injection/references/task_prompts/task_22_injection_review.md`
- `sec-scan-xss/references/task_prompts/task_23_xss_review.md`
- `sec-scan-file/references/task_prompts/task_24_file_handling.md`
- `sec-scan-data/references/task_prompts/task_25_data_protection.md`
- `sec-scan-sca/references/task_prompts/task_sca_llm_review.md`

---

## 대형 Repo / 멀티 build_target 진단

> **적용 조건**: API inventory endpoints > 1,000 또는 Gradle submodule 복수인 대형 repo
>
> 상세 절차: `shared/references/large_repo_multi_module.md`
>
> **핵심 원칙**:
> - `scan_injection_enhanced.py` / `scan_xss.py` → `--modules <build_target>` 으로 분리 실행
> - `scan_file_processing.py` / `scan_data_protection.py` / `scan_sca_gradle_tree.py` → 전체 repo 1회 실행
> - build_target별 독립 prefix: `state/<prefix>_<BT>/`

## 미지원 언어 처리

> PHP / Python / Go 등 미지원 언어 repo → 자동 스캔 전량 skip
> 대상 목록: `shared/references/unsupported_lang_targets.md`

---

## 진단 범위 제한 (Module-Scoped Audit)

> **적용 조건**: 진단 대상이 repo 전체가 아니라 **특정 서브모듈/패키지 경로**만 해당할 경우

- `scan_injection_enhanced.py --modules <module>` 으로 범위 제한
- `scan_xss.py --modules <module>` 으로 범위 제한
- file/data/sca 스캔은 전체 repo 실행 후 LLM-Check 단계에서 모듈 범위 필터링
