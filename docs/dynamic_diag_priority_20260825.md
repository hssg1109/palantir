# 동적 진단(모의해킹) 대상 레포 우선순위 목록

> 작성일: 2026-08-25
> 대상: SAST 진단 완료 후 `/sec-review` §5d 절차에 따라 "동적 진단 필요"로 판정된 레포 중, 실제 모의해킹 착수 우선순위를 선정한 목록
> 선정 기준: ① 대외 노출 + Critical/High 정탐 다수, ② 결제·포인트 등 금전적 직접 조작 가능성, ③ PoC 시나리오가 엔드포인트·파일:라인까지 구체적으로 문서화되어 실증 착수 비용이 낮은 것

## Tier 1 — 최우선

| 레포 | 노출 | 정탐(C/H/M) | 진단 유형 | PoC 근거 | 보고서 / 티켓 |
|---|---|---|---|---|---|
| `ocb-fnc-webview-api` | 🌐 대외 | 2/20/7 | 인증, 결제, XSS PoC | SOI 세션인증+JOSE 암호화 기반 포인트교환/UPTN코인충전이체 금융거래 처리. 전역 XSS 필터 완전 미구현 + 포인트전환실행 API Persistent XSS(XSS-002, High)로 세션 탈취 실증 필요. UptnController 하드코딩 clientSecret도 확인 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=758448162) / [JIRA:SECUFINDINGS-2114] |
| `ocb-event-server` | 🌐 대외 | 3/6/1 | XSS PoC | `POST /api/short-form/events/{eventId}/participation` → `ShortFormEventParticipationController.participate()` 경로로 이벤트 참여 입력값이 미정제 상태로 DB 저장 → 관리자/타 사용자 렌더링 시 Stored XSS로 세션 탈취 실증 가능 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=754239806) / [JIRA:SECUFINDINGS-2140] |
| `ocb-joy-api` | 🌐 대외 | 1/12/5 | 개인정보, 결제 | `POST /api/v1.0/jackpot/gift/apply` 응답값에 전화번호/실명 비마스킹 노출(High) — 실제 호출로 PII 노출 실증 가능. 게이미피케이션 포인트지급 로직 어뷰징 위험 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=752837309) / [JIRA:SECUFINDINGS-2120] |
| `ocb-webview-api` | 🌐 대외 | 1/12/6 | 인증, 결제, XSS PoC | 79개 Controller 규모 앱 웹뷰 핵심 API — 포인트/결제/KCP·카카오페이·네이버페이 PG연동. KCP 결제콜백 JSP 3종 HTML escape 미처리(High)로 결제플로우 XSS 실증 가능, PII 비마스킹 103건 실제 노출범위 실증 필요 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=750464899) / [JIRA:SECUFINDINGS-2118] |
| `ocbws-web-api` | 🌐 대외 | 1/12/3 | 인증, 결제, XSS PoC | `POST /api/{version}/auth/withdraw/reasons`의 `etcReason` 필드가 XSS 필터링 없이 DB 저장 → 관리자 화면 렌더링 시 Stored XSS로 관리자 세션 탈취 실증 가능. 전역 필터 미구현으로 50개 엔드포인트 동일 패턴 노출 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=754235600) / [JIRA:SECUFINDINGS-2136] |
| `ocb-iam` | 🌐 대외 | 1/7/2 | 인증 | OAuth 2.0 인증코드/토큰 발급 서버 자체. `IamAuthController.kt:119,123`에서 OAuth 인증코드가 info레벨 로그에 평문기록 → 로그 접근자가 인증코드 유출 타이밍을 악용해 토큰교환 API를 선점 호출하는 계정탈취 시나리오 실증 가능. 인증 우회 성공 시 연동 서비스 전체로 파급 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=758474078) / [JIRA:SECUFINDINGS-2135] |

## Tier 2 — 차순위 (실증 착수비용 낮음 / 특정 취약점 명확)

| 레포 | 노출 | 정탐(C/H/M) | 진단 유형 | PoC 근거 | 보고서 / 티켓 |
|---|---|---|---|---|---|
| `thirdparty-api-kt` | 🌐 대외 | 0/7/0 | 인프라(NCP키), XSS PoC | `NaverCloudService.kt:25` 주석처리된 `@Value` 대신 리터럴 하드코딩된 NCP IAM Access/Secret Key가 실제 API 인증헤더에 사용 → 저장소 접근만으로 NCP Live Station API 무단 제어 실증 가능. 제휴 방송 등록 API Persistent XSS도 동반 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=763722864) / [JIRA:SECUFINDINGS-2147] |
| `main-api-on-lambda-kt` | 🌐 대외 | 1/0/1 | 인프라, PoC 실증 | `AwsResourceEndpointHandler`(`/aws/*`) 전체 라우트가 인증 없이 Secrets Manager/S3/SQS/Redis에 접근 가능 — 운영 환경에서 실제 살아있는지 블랙박스 curl 실증 필요 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=763711655) / [JIRA:SECUFINDINGS-2153] |
| `ocb-webview-reward-api` | 🌐 대외 | 0/11/4 | 인증, 결제 | `spring-security-core` 5.6.6 CVE-2022-31692(CVSS 9.8) FORWARD/INCLUDE Dispatcher 인증우회 가능성 + 포인트 적립/ACL API Persistent XSS — 인증우회와 포인트 조작 조합 실증 필요 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=754226017) / [JIRA:SECUFINDINGS-2123] |
| `cashbagmall` | 🌐 대외 | 0/7/5 | 인증, 결제 | 대외 노출 프론트 API(쿠폰/쇼핑 적립) 전역 XSS 필터 부재, AES 키 하드코딩 확인 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=767331905) / [JIRA:SECUFINDINGS-2168] |
| `event_resource` | 🔒 대내 | 0/7/1 | 인증(OTP우회), Redirect PoC | OTP(`CheckPlusOtpAPI.java:23`) HMAC/JWT 서명키 및 SKT연동(`SktMemberDootoomResource.java:57`) AES 복호화키 하드코딩 → 본인인증 우회 실증 가능. 대내 전용망 서비스로 외부 공격면은 제한적이나 인증우회 파급력이 커 포함 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=767337216) / [JIRA:SECUFINDINGS-2157] |

## 참고 — 우선순위 하향 (최근 동적진단 진행)

| 레포 | 노출 | 정탐(C/H/M) | 진단 유형 | 비고 | 보고서 / 티켓 |
|---|---|---|---|---|---|
| `ocb-community-api` | 🌐 대외 | 4/10/5 | 인증, 개인정보, SQLi PoC | 최근 관련 동적 진단을 이미 진행하여 재실시 우선순위를 뒤로 미룸. SQLi(`FeedQuery.kt:1754`), `NoOpPasswordEncoder` 인증체계 우회 등 미실증 항목은 후속 라운드에서 재검토 | [보고서](https://wiki.skplanet.com/pages/viewpage.action?pageId=752826752) / [JIRA:SECUFINDINGS-2117] |

---
> 각 레포 상세 SAST 결과는 `docs/ocb_scan_plan.md` 진단 체크리스트 및 개별 최종 보고서(위키 링크) 참조.
