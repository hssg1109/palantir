# Task 31 — 이행점검 Finding별 재검증 절차

`/sec-scan-remediation` Phase 3에서 검증 대상 finding 각각에 대해 수행하는 절차.

## 입력

- 원본 finding (`state/<repo>/<skill>/<run_id>/findings_*.json`에서 매칭된 항목)
  - `scope.affected_file`, `scope.line`(또는 `scope.endpoint`), `category`, `description`,
    `code_snippet`, `severity`, `finding_id`
- Phase 1에서 확보한 리뷰어 코드분석 요약(`auditor.code_analysis_summary`, 있는 경우)
- `targets.json`의 해당 target (`dev_reply` 포함)
- 최신 clone 소스 (`testbed/<repo>/`)

## 절차

### 0. Carry-forward 확인 (2차 이상 실행 시)
- Phase 1에서 이 target이 `carry_forward=true`로 표시되어 있으면(직전 회차 동일 티켓에서
  `조치완료` 확인됨), **아래 1~6단계를 전부 생략**하고 이전 `verdict`/`note`/`checked_at`을
  그대로 결과에 채운 뒤 종료한다. 코드를 다시 열어보지 않는다.
- `carry_forward=false`(또는 `--full` 실행)인 경우에만 1번부터 정상 진행한다.

### 1. 원본 위치 재탐색
- `scope.affected_file` 경로가 `testbed/<repo>/` 아래 그대로 존재하는지 Read/Glob으로 확인
- 없으면 파일명(basename)으로 Glob 재탐색 (리네임/모듈 이동 대응)
- 그래도 없으면 **판정 = 확인불가**, note = "원본 파일 경로 소실 — {원본경로}"로 즉시 종료

### 2. 현재 코드 로드
- 원본 `scope.line` 기준 ±15줄을 Read (SCA는 이 단계 skip, 4번으로)
- 원본 `code_snippet`과 현재 코드를 나란히 비교

### 3. 원 skill 진단기준 재적용
- finding의 `category`로 원 skill을 판별 (INJ/XSS/FILE/DATA)
- 해당 skill의 `references/*_diagnosis_criteria.md` (또는 동급 기준 문서)를 그대로 열어
  "이 코드가 그 기준으로 여전히 취약/정보/양호 중 무엇인가"를 판단
- 새로운 유형의 취약점을 여기서 발견해도 이 skill의 scope 밖 — note에만 언급하고 판정에는 반영하지 않음
  (신규 발견은 `/sec-scan-*` 재실행으로 별도 처리해야 함을 결과 요약에 안내)

### 4. SCA 예외 처리
- `category`가 `SCA/CVE`(또는 skill == "sca")면 코드 대신:
  - `pom.xml` / `build.gradle(.kts)` / `package.json` (원본 `scope.file`)에서 해당 패키지의
    선언 버전을 재파싱
  - `evidence.fixed_version`과 semver 비교: 이상이면 **조치완료**, 미만이면 **미조치**
  - 버전을 특정할 수 없으면(BOM/부모 POM 상속 등) **확인불가**

### 5. 개발자 회신 대조
- `dev_reply.조치 계획`이 있으면, 실제 코드 변경 내용과 비교
- 불일치 시 note에 명시. 일치 여부가 판정을 바꾸지는 않음 (판정은 항상 코드 근거 우선)

### 6. 판정 확정
- `remediation_verdict_criteria.md`의 4단계(조치완료/미조치/부분조치/확인불가) 중 하나로 확정
- note에는 반드시 판정 근거(어느 라인이 어떻게 바뀌었는지/안 바뀌었는지)를 한국어로 명시
- 애매한 경우 상향(조치완료) 금지 원칙 재확인 후 확정

## 출력 (finding 1건당)

```json
{
  "finding_id": "INJ-003",
  "sub_no": "1-1",
  "verdict": "조치완료",
  "note": "42번 라인 문자열 결합 쿼리가 PreparedStatement 파라미터 바인딩으로 교체됨 (commit abcd123)",
  "matched": true,
  "carried_forward": false
}
```

carry-forward(0단계에서 생략한 경우) 출력 예:
```json
{
  "finding_id": "DATA-002",
  "sub_no": "2-2",
  "verdict": "조치완료",
  "note": "Redis 비밀번호 평문 → Jasypt ENC(...) 암호화로 교체 확인 (application-dev.yaml, application-local.yaml)",
  "matched": true,
  "carried_forward": true,
  "carried_forward_from": "2026-07-15"
}
```
