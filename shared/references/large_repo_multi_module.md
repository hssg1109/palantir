# Large Repo Multi-Module 진단 절차

> **적용 조건**: 하나의 repo에 Fortify build_target이 복수이거나, API 인벤토리 endpoints 수가 많아 단일 스캔 시 timeout/context 초과가 우려되는 경우.

---

## 판정 기준 — 이 절차를 적용해야 하는 경우

| 조건 | 기준 | 대응 |
|---|---|---|
| 멀티 모듈 repo | Fortify build_target ≥ 2 | 필수 적용 |
| 대형 단일 repo | API inventory endpoints > 1,000 | 필수 적용 |
| 보통 크기 | endpoints ≤ 1,000, build_target = 1 | 일반 전체 스캔 (Phase 2.5 불필요) |

> ob-backend 경험: 4,176 endpoints → `scan_injection_enhanced.py` timeout 발생.
> `--modules <build_target>` 으로 분리하면 build_target 당 평균 800~1,000 endpoints → 정상 완료.

---

## 기본 원칙

```
┌─────────────────────────────────────────────────────────────────────┐
│  Multi-Module 진단 흐름                                              │
│                                                                     │
│  Phase 2a: 전체 repo 1회 스캔 (file_processing / data_protection)   │
│      ↓                                                              │
│  Phase 2b: build_target별 injection/xss 스캔 (--modules 사용)        │
│      ↓                          ↓                                   │
│  [build_target A]         [build_target B]  ...                     │
│   Phase 2.5 inscope        Phase 2.5 inscope                        │
│   Phase 3 LLM              Phase 3 LLM                              │
│   Phase 4 보고서/게시       Phase 4 보고서/게시                        │
│      ↓                          ↓                                   │
│  SCA: 전체 repo 1회 (build_target 공유 의존성 기준)                    │
└─────────────────────────────────────────────────────────────────────┘
```

- **공유 스캔 (전체 repo 1회)**: `scan_file_processing.py`, `scan_data_protection.py`, `scan_sca_gradle_tree.py`
- **분리 스캔 (build_target별)**: `scan_injection_enhanced.py --modules`, `scan_xss.py --modules`
- **전체 repo 원본 JSON 은 삭제하지 않음** — 증거 보존

---

## Step 0: Build-Target 목록 확인

```bash
# Gradle 멀티모듈 구조 확인
cat testbed/<repo>/settings.gradle | grep include

# API inventory 실행 후 module 필드 확인
python3 shared/scripts/scan_api.py testbed/<repo> -o state/<prefix>/api_inventory.json
python3 -c "
import json
from collections import Counter
d = json.load(open('state/<prefix>/api_inventory.json'))
mods = Counter(ep.get('module','') for ep in d.get('endpoints',[]))
print('총 endpoints:', sum(mods.values()))
for k,v in mods.most_common():
    print(f'  {v:4d}  {k}')
"
```

**Fortify build_target ↔ API inventory `module` 필드 매핑 확인**:
- Fortify `build_target`명 = Gradle submodule 디렉토리명 = `module` 필드값
- 불일치 시 `module` 필드값 기준으로 `--modules` 인수 결정

---

## Step 1: 공유 스캔 (전체 repo, 1회)

> scan_file_processing / data_protection / sca 는 build_target 구분 없이 전체 repo 대상 1회 실행.

```bash
PREFIX_REPO="state/<test_prefix>_<repo>"   # 예: state/t41_ob_backend

# 파일 처리 (전체 repo)
python3 shared/scripts/scan_file_processing.py testbed/<repo> \
    -a state/<prefix>/api_inventory.json \
    -o ${PREFIX_REPO}_task24.json

# 데이터 보호 (전체 repo)
nohup python3 shared/scripts/scan_data_protection.py testbed/<repo> \
    -o ${PREFIX_REPO}_task25.json > state/scan_dp.log 2>&1 &

# SCA (전체 repo)
python3 shared/scripts/scan_sca_gradle_tree.py testbed/<repo> \
    --project <repo_name> -o ${PREFIX_REPO}_sca.json
```

---

## Step 2: Build-Target별 분리 스캔

각 Fortify build_target마다 독립 prefix 사용:

```bash
# build_target 목록 예시: cms_resource, event_resource
BUILD_TARGETS=("cms_resource" "event_resource")

for BT in "${BUILD_TARGETS[@]}"; do
    PREFIX="state/<test_prefix>_${BT}"
    echo "=== Scanning: $BT ==="

    # Injection 스캔 (--modules 사용)
    nohup python3 shared/scripts/scan_injection_enhanced.py \
        testbed/<repo> \
        -a state/<test_prefix>_<repo>_api_inventory.json \
        --modules "$BT" \
        --source-root testbed/<repo> \
        -o ${PREFIX}_injection.json > state/scan_injection_${BT}.log 2>&1 &
    echo "injection PID: $!"

    # XSS 스캔 (--modules 사용)
    nohup python3 shared/scripts/scan_xss.py \
        testbed/<repo> \
        -a state/<test_prefix>_<repo>_api_inventory.json \
        --modules "$BT" \
        -o ${PREFIX}_xss.json > state/scan_xss_${BT}.log 2>&1 &
    echo "xss PID: $!"
done
```

> injection / xss 는 build_target별 개별 prefix(`state/<test_prefix>_<BT>_injection.json`)로 저장.

---

## Step 3: Build-Target별 Phase 2.5 — inscope JSON 생성

공유 스캔 결과(task24/task25)를 build_target별로 필터링.

```python
import json, copy

REPO_PREFIX = "state/<test_prefix>_<repo>"   # 공유 스캔 파일 prefix
BT          = "cms_resource"                  # 현재 build_target
BT_PREFIX   = f"state/<test_prefix>_{BT}"    # build_target 전용 prefix
SCOPE       = (BT,)                          # module 필드 키워드

def in_scope(path):
    return any(s in (path or '') for s in SCOPE)

# API 인벤토리 → build_target별 inscope
with open(f"{REPO_PREFIX}_api_inventory.json") as f: api = json.load(f)
api_f = copy.deepcopy(api)
orig = api.get("endpoints", [])
api_f["endpoints"] = [e for e in orig if in_scope(e.get("file","") + e.get("module",""))]
api_f["original_endpoint_count"] = len(orig)
with open(f"{BT_PREFIX}_api_inventory_inscope.json", "w") as f:
    json.dump(api_f, f, ensure_ascii=False, indent=2)

# Injection은 분리 스캔했으므로 전체가 inscope → 그대로 복사
import shutil
shutil.copy(f"{BT_PREFIX}_injection.json", f"{BT_PREFIX}_injection_inscope.json")
shutil.copy(f"{BT_PREFIX}_xss.json",       f"{BT_PREFIX}_xss_inscope.json")

# Data Protection → build_target별 필터링
with open(f"{REPO_PREFIX}_task25.json") as f: t25 = json.load(f)
t25_f = copy.deepcopy(t25)
t25_f["findings"] = [x for x in t25.get("findings",[]) if in_scope(x.get("file",""))]
with open(f"{BT_PREFIX}_task25_inscope.json", "w") as f:
    json.dump(t25_f, f, ensure_ascii=False, indent=2)

# File Processing → build_target별 필터링
with open(f"{REPO_PREFIX}_task24.json") as f: t24 = json.load(f)
t24_f = copy.deepcopy(t24)
t24_f["findings"] = [x for x in t24.get("findings",[]) if in_scope(x.get("file",""))]
with open(f"{BT_PREFIX}_task24_inscope.json", "w") as f:
    json.dump(t24_f, f, ensure_ascii=False, indent=2)
```

> 위 코드를 build_target별로 `BT` 변수만 바꿔 반복 실행.

---

## Step 4: Build-Target별 Phase 3 LLM 분석

각 build_target의 `_inscope.json`을 입력으로 LLM 수동 분석 수행.

```
입력: <test_prefix>_<BT>_injection_inscope.json  →  출력: <test_prefix>_<BT>_task22_llm.json
입력: <test_prefix>_<BT>_xss_inscope.json        →  출력: <test_prefix>_<BT>_task23_llm.json
입력: <test_prefix>_<BT>_task24_inscope.json     →  출력: <test_prefix>_<BT>_task24_llm.json
입력: <test_prefix>_<BT>_task25_inscope.json     →  출력: <test_prefix>_<BT>_task25_llm.json
```

SCA LLM 검토는 전체 repo 공유 결과 기준으로 1회만 수행:
```
입력: <test_prefix>_<repo>_sca.json  →  출력: <test_prefix>_<repo>_sca_llm.json
```

---

## Step 5: 대형 repo 최소토큰 타겟 진단 — 실제 취약 case만 리뷰

> 적용 대상: Step 0 기준으로 이 절차가 적용된 대형/멀티모듈 repo. Auto-Scan의 "정보/수동확인필요" 건수가 모듈당 수백~수천 건으로 나오는 경우, 전수 개별 리뷰 대신 아래 방식으로 실제 취약 case에만 리소스를 집중한다.
>
> **핵심 원칙**: 아래는 검토를 생략하는 것이 아니라 **검토 결과를 압축해서 리포팅**하는 것이다. 판정 기준(FP/TP, Tier1/Tier2, criteria 문서의 기준)은 그대로 엄격히 적용하고, 대표사례·파일단위·그룹단위로 묶는 것은 리포팅 단계에서만 적용한다. **실제 취약(High/Critical 확정) 건은 절대 축약하지 않는다** — 축약 대상은 정보/저위험/구조적 반복 패턴에 한정.

### 5-1. Injection — `${}` 역추적(reverse-taint) 우선

기존 절차(Tier1/Tier2, `task_22_injection_review.md`)는 유지하되, **검토 방향을 endpoint 단위(정방향)가 아니라 `${}` 사용 지점 단위(역방향)로 전환**한다.

1. Auto-Scan 결과에서 `${}` 가 실제 등장하는 mapper XML / SQL ID를 먼저 전수 나열한다 (endpoint 수보다 훨씬 적음 — 보통 mapper 파일당 1~수 개).
2. 각 `${}` 사용 지점에서 **역방향**으로 호출자를 추적한다: Mapper → DAO/Repository 메서드 → Service → Controller.
   - 해당 파라미터가 HTTP 요청(`@RequestParam`/`@PathVariable`/`@RequestBody`/Header/Cookie)에서 오는지, 내부 생성값(날짜 포맷, enum, 시스템 상수, 배치 스케줄러 값)인지 확인한다.
3. 판정:
   - **내부 생성값만 유입** → Tier1(잠재적 취약, 최소 등급) 고정, Tier2 격상 안 함. `manual_review_note`에 "HTTP 파라미터 미도달, 값 출처: <구체 경로>" 명시.
   - **HTTP 파라미터 직접 도달 확인** → Tier2(매우 취약) 확정.
4. **한 번의 역추적으로 해당 SQL ID를 호출하는 모든 endpoint를 동시에 처리** — 같은 mapper 메서드를 호출하는 endpoint 여러 개를 각각 정방향으로 재추적하지 않는다 (`group_judgments`에 소속 endpoint 전체를 묶어 기록).
5. `자동 판정 불가`/`DB 접근 미확인` 등 taint-tracking-failure 그룹은 기존처럼 `group_judgments`로 사유별 일괄 처리.

### 5-2. XSS Persistent — Sink 도달 + Data Type 게이트를 실제로 적용

`task_23_xss_review.md`의 "Persistent XSS 식별 3원칙"(Sink 도달 여부 → Data Type → Async Taint Break)을 **모든 root_cause/instance 건에 실제로 적용**한다 — "저장 시점 필터 미적용 = 취약"이라는 보수적 기본값을 이유로 원칙 적용 자체를 생략하지 않는다.

- 원칙1(DB Write 없음) 또는 원칙2(숫자/Enum/UUID/Hash 타입) 충족이 확인되면 **그 즉시 FP(양호)** 처리 — evidence_trail로 이동.
- 자유 텍스트(String) 필드 저장 + 필터 없음이 실제로 확인된 case만 최종 취약으로 카운트한다.
- `instance` finding 중 **동일 파일/동일 코드 패턴**(같은 JSP/Thymeleaf 템플릿, 여러 endpoint가 매핑되는 동일 Controller 메서드 등)을 공유하는 건은 `affected_files[]`로 묶어 1건으로 리포팅 — 대표 파일 1회만 코드 추적한다.
- **2단계 병합(필수)**: 파일 단위로 묶은 그룹(1차 그룹핑)이 수십~수백 개로 나올 경우, 거기서 멈추지 말고 **동일 근본원인(root cause) 패턴 기준으로 2차 병합**한다 — 예: "naked EL `${value}` 미이스케이프", "`escapeXml=\"false\"` 명시적 비활성화" 등 패턴이 같으면 파일이 몇 개든 **하나의 finding**으로 합치고 `affected_files[]`에 전체 파일 목록(경로+건수)만 나열한다. "파일별로 그룹핑했으니 끝"이 아니라 "그룹 개수 자체가 최종 finding 개수"라는 점을 명심할 것 — 대형 CMS/View 모듈에서 파일-그룹 수백 개를 그대로 수백 개의 개별 finding으로 리포팅하는 것은 Step 5의 취지(리포팅 압축)에 반한다. 최종 finding 개수는 "발견된 근본원인 패턴 수" 규모(한 자릿수~두 자릿수)를 넘지 않아야 한다.
- Kafka/MQ 경유는 원칙3(Async Taint Break, 보수적 카운팅) 그대로 유지 — Consumer 미확인 시에도 취약 카운트에 포함(FP 금지).

### 5-3. Data / HARDCODED_SECRET — 파일 단위 최소화 + 테스트·더미 값 선별

- 병합(RULE-2, 파일/환경 단위) 전에 **테스트/더미/예시 자격증명 패턴**(변수명·값에 `test`, `dummy`, `sample`, `example`, `local`, `xxxx`, `changeme` 등 포함)을 먼저 걸러내고, 실사용 가능성이 있는 값만 병합 대상으로 리포팅한다.
- 병합 후 finding 수는 원칙적으로 "파일 수" 이하로 유지 (동일 파일 내 여러 시크릿은 1 finding).

### 5-4. Data / SENSITIVE_LOGGING — 대표 case + 권고 축약

- RULE-1(레포 전체 2버킷 병합: DATA-LOG-001 Critical/info·warn·error·fatal, DATA-LOG-002 Medium/debug·trace)은 그대로 적용하되, **개별 로그 라인을 모두 순회하지 않는다.**
- 대표 파일:라인 2~3건만 `evidence.code_snippet`으로 인용하고, `description`에 "외 N건, 동일 패턴" 명시.
- `recommendation`은 일반적인 마스킹/필터링 가이드 수준으로 축약 (예: PII 마스킹 유틸 적용, 로그레벨 정책 조정) — 건별 맞춤 권고 작성은 생략한다.

### 5-5. Data / DTO_EXPOSURE — 2-트랙 분리

RULE-3을 다음 2트랙으로 명확히 나눠 적용한다:

| 트랙 | 조건 | 처리 방식 |
|---|---|---|
| **A. 구조적(간접) 노출** | `@ToString`/Lombok 등으로 Entity에 PII 필드가 존재하나, 실제 API 응답 직렬화 여부 미확인 또는 간접적 | 대표 DTO 클래스 몇 건만 샘플링, `Medium`, 리스트 형태로 축약 리포팅 (권고 위주) |
| **B. 확정(직접) 노출** | Controller 코드에서 해당 DTO가 실제로 API 응답(JSON body)에 그대로 직렬화되어 반환됨을 코드로 확인 | **샘플링 금지 — 확인된 건 전부 개별 finding으로 분리 리포팅**, `High`, 실제 endpoint/필드명 명시 |

> 트랙 B는 절대 대표사례로 뭉뚱그리지 않는다 — 실제 PII가 API로 나가는 case는 축소 없이 전수 리포팅한다.

---

## Prefix 네이밍 컨벤션

| 항목 | 패턴 | 예시 |
|---|---|---|
| 전체 repo 공유 스캔 | `<test_prefix>_<repo>_` | `t41_ob_backend_` |
| build_target별 스캔 | `<test_prefix>_<BT>_` | `t41_cms_resource_` |
| API inventory | `<test_prefix>_<repo>_api_inventory.json` | 공유 (build_target 구분 없음) |
| SCA | `<test_prefix>_<repo>_sca.json` | 공유 |
| Task 11 | `<test_prefix>_<repo>_task11.json` | 공유 |
| Injection/XSS | `<test_prefix>_<BT>_injection.json` | build_target별 |
| Task22~25 LLM | `<test_prefix>_<BT>_task22_llm.json` | build_target별 |
---

## 미지원 언어 repo 처리

스캐너가 지원하지 않는 언어(PHP 등)는 자동 스캔을 생략하고 아래로 처리:
- Phase 2 자동 스캔 전량 skip
- `references/unsupported_lang_targets.md` 에 미지원 대상 목록 기록
- 향후 해당 언어 스캐너 구현 후 재진단

지원 언어 현황:
| 언어 | 지원 여부 | 비고 |
|---|---|---|
| Java | ✅ | 전체 지원 |
| Kotlin | ✅ | 전체 지원 |
| TypeScript/JavaScript | ✅ (부분) | XSS/DataProtection 중심, Injection 제한적 |
| PHP | ❌ | 미지원 — `unsupported_lang_targets.md` 참조 |

