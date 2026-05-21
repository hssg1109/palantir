# Severity Criteria — 취약점 위험도 등급 기준

> **근거 규정**
> - 전자금융감독규정 제37조의3 (전자금융기반시설 취약점 분석·평가)
> - 주요 정보통신기반시설 보호지침(과학기술정보통신부 고시 제2021-28호)
> - 금융보안원 소프트웨어 보안약점 진단 가이드
>
> 위 규정에 명시된 취약점 유형별 등급을 우선 적용한다.
> **규정에 명시되지 않은 취약점**은 LLM이 영향도·악용 가능성·전자금융 서비스 특수성을 종합 판단하여
> 아래 등급 정의에 따라 자율 배정한다.
>
> **적용 범위**: palantir 전체 skill (auto-scan 스크립트 + LLM-check 단계)

---

## 등급 정의

| 등급 | 영문 (severity 내부값) | 명칭 | 의미 / 정의 | 대표 영향 | 조치 방침 |
|:---:|:---:|:---:|---|---|---|
| **5** | `Critical` | 매우위험 | 공격 성공 시 즉시 금전 손실·계정 탈취·시스템 장악 등 심각한 피해 가능성이 매우 높음 | 원격 코드 실행, 인증 우회, 거래 위변조, 세션 탈취 | 즉시 조치 |
| **4** | `High` | 고위험 | 직접적 피해 가능성 높음. 민감정보 노출·권한 상승·서비스 악용 가능 | XSS, SSRF, 인증 우회, 디렉토리 인덱싱 | 우선 조치 |
| **3** | `Medium` | 중간위험 | 설정 오류·구성 문제로 보안 수준 약화. 다른 취약점과 결합 시 악용 가능 | 취약한 HTTPS 구성, 인증서 오류, 백그라운드 정보 노출 | 검토 후 조치 |
| **2** | `Low` | 저위험 | 직접 영향 낮음. 특정 조건에서 악용 가능 | 재협상 취약한 HTTPS 설정 등 | 개선 권고 |
| **1** | `Informational` | 매우낮음 | 악용까지 거리가 멀거나 운영상 거의 영향 없음 | 불필요한 메서드 허용 등 | 참고 |

> **표시 원칙**: 보고서 외부(Confluence 위험도 컬럼 등)는 **`N등급 명칭`** 형식으로 표시 (예: `5등급 매우위험`, `4등급 고위험`). `Critical/High` 등 영문값은 finding JSON `severity` 필드 전달 전용이며 보고서에는 노출하지 않는다. `risk_level` (정수 1~5) 필드는 finding 생성 시 반드시 포함.

---

## 취약점 유형별 등급 매핑

### 규정 명시 항목 (주요 정보통신기반시설 보호지침 / 전자금융감독규정)

| 취약점 유형 | 등급 | severity 내부값 | palantir skill |
|-----------|:---:|:---:|---|
| SQL Injection (확정) | 5 | `Critical` | sec-scan-injection |
| SQL Injection (잠재, 수동확인 필요) | 4 | `High` | sec-scan-injection |
| 운영체제 명령실행 (OS Command Injection) | 5 | `Critical` | sec-scan-injection |
| SSI Injection | 5 | `Critical` | sec-scan-injection |
| 악성파일 업로드 (웹쉘 등) | 5 | `Critical` | sec-scan-file |
| 파일 다운로드 취약 (Path Traversal / LFI) | 5 | `Critical` | sec-scan-file |
| 크로스 사이트 스크립팅 (XSS) | 4 | `High` | sec-scan-xss |
| 리다이렉트 기능 피싱 (Open Redirect) | 4 | `High` | sec-scan-xss |
| 서버 사이드 요청 위조 (SSRF / RFI) | 4 | `High` | sec-scan-file |
| 디버그 로그 내 중요정보 노출 (info/warn/error/fatal) | 5 | `Critical` | sec-scan-data |
| 서버 사이드 템플릿 인젝션 (SSTI) | 5 | `Critical` | sec-scan-xss |

### LLM 판단 항목 (규정 미명시 — 영향도·맥락 기반 자율 배정)

> 아래 항목은 규정에 직접 등급이 명시되지 않아 LLM이 코드 맥락과 위 등급 정의를 참고해 배정한다.

| 취약점 유형 | 기본 판단 기준 | palantir skill |
|-----------|------------|---|
| JWT Algorithm NONE 허용 | 인증 완전 우회 → 5등급(Critical) 유력 | sec-scan-data |
| JWT parseUnsecuredClaims() 사용 | 인증 완전 우회 → 5등급(Critical) 유력 | sec-scan-data |
| AWS/GCP 클라우드 키 하드코딩 | 외부 시스템 장악 가능성 → 5등급(Critical) 유력 | sec-scan-data |
| DB 비밀번호/JWT Secret 하드코딩 | 민감정보 직접 노출 → 4등급(High) 유력 | sec-scan-data |
| JWT 서명 키 미설정 | 토큰 위조 가능 → 4등급(High) 유력 | sec-scan-data |
| JWT 클럭 스큐 과도 설정 | 조건부 토큰 재사용 → 3등급(Medium) 유력 | sec-scan-data |
| 취약한 암호 알고리즘 (MD5/SHA-1/DES/ECB) | 암호 해독 가능 → 3등급(Medium) 유력 | sec-scan-data |
| NoOpPasswordEncoder / Md5PasswordEncoder | 패스워드 평문/취약 해시 → 5등급(Critical) 유력 | sec-scan-data |
| CORS allowedOrigins(*) + allowCredentials(true) | 크로스 오리진 자격증명 탈취 → 3등급(Medium) 유력 | sec-scan-data |
| CORS Origin 헤더 동적 반영 | 조건부 악용 → 3등급(Medium) 유력 | sec-scan-data |
| 보안 헤더 비활성화 (.headers().disable() 등) | 보안 수준 약화 → 3등급(Medium) 유력 | sec-scan-data |
| DTO 민감 필드 @JsonIgnore 미적용 | 민감정보 노출 → 4등급(High) 또는 3등급(Medium) | sec-scan-data |
| PII Logging (debug/trace 레벨) | 운영환경 노출 가능성 낮음 → 1등급(Informational) 유력 | sec-scan-data |
| 파일 업로드 부분 검증 미흡 | 악용 조건에 따라 3~5등급 LLM 판단 | sec-scan-file |
| CVE (SCA) | CVSS 점수 참고 후 코드 실사용 여부 종합 판단 | sec-scan-sca |

---

## severity 내부값 통일 표

모든 palantir 스크립트는 아래 **5종 영문값만** severity 필드에 기록한다.

| severity 내부값 | 등급 | 명칭 |
|:---:|:---:|:---:|
| `Critical` | 5 | 매우위험 |
| `High` | 4 | 고위험 |
| `Medium` | 3 | 중간위험 |
| `Low` | 2 | 저위험 |
| `Informational` | 1 | 매우낮음 |

> `Risk 1~5`, `Info` 등 이전 표기는 폐기. 모든 스크립트 출력에서 위 5종만 사용.

---

## 변경 이력

| 날짜 | 요약 |
|------|------|
| 2026-04-14 | 주요 정보통신기반시설 보호지침(과학기술정보통신부 고시 제2021-28호) 기반 전면 개정. `Risk 1~5` / `Info` 폐기 → `Critical/High/Medium/Low/Informational` 5종 통일. 규정 미명시 항목은 LLM 판단 원칙 추가. |
| 2026-03-17 | 전자금융감독규정·주요 정보통신기반시설 보호지침 기반 위험도 1~5 기준 재정의. High/Critical 영문 표기 폐기, 위험도 숫자+결과(취약/정보/양호) 단일 체계로 전환. |
| 2026-03-09 | 사내 공식 취약점 등급 기준서 기반 전면 개정 |
| 초기 | Grade 5→Critical ... Grade 1→Info 단순 매핑만 정의 |
