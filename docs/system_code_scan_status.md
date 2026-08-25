# 전사 시스템코드별 Palantir 보안진단 현황

:::info 문서 정보
**작성일**: 2026-08-12

**원본 데이터**: `docs/system_code_to_repo_20260729_v3.json` (전사 CMDB 시스템코드 매핑, 297개)
:::

:::note
⚙️ 본 현황은 **palantir 진단 도구**(`state/` 실행 이력) 기반 자동 집계이며, Fortify 등 타 도구 진단 이력은 포함하지 않음.
:::

:::tip
🗂️ **상위 서비스군**은 시스템명 접두어 기반 휴리스틱 분류(`tools/system_code_lookup.py::classify_group()`) — 참고용이며 100% 정확을 보장하지 않음.
:::

## 0. 전사 집계 요약

- 시스템코드: 전체 297개 (레포 매핑 있음 159개 / 레포 미확인 138개)
- 레포: 시스템코드-레포 매핑 1062건 (고유 레포 768개, 동일 레포가 복수 시스템코드에 걸치는 경우 있음)
- 고유 레포 기준 진단 현황: 진단완료 69개 / 부분진단 0개 / 미진단 699개
- 1개 레포가 여러 시스템코드에 매핑된 경우: 152건 (§3 참조, 실제 소속 시스템코드 확인 필요)

## 1. 시스템코드별 요약

> 🟢 **시스템코드 진단완료**(매핑된 레포 전체가 injection/xss/file/data 4종 모두 완료) 8개 — 아래 표의 색상 플래그 열 참조.

| 상위 서비스군 | 시스템코드 | 시스템명 | 레포수 | 진단완료 | 부분진단 | 미진단 | 시스템 진단완료 | 비고 |
|---|---|---|---|---|---|---|---|---|
| BI | `C001302` | BI서비스-Voyager | 2 | 0 | 0 | 2 |  |  |
| BI | `C001706` | BI서비스-ANALOG | 5 | 0 | 0 | 5 |  |  |
| BI | `C001778` | BI서비스-DIIF | 14 | 0 | 0 | 14 |  |  |
| BI | `C001854` | BI서비스-API | 2 | 0 | 0 | 2 |  |  |
| DI(데이터인프라) | `C000950` | DI-Galleon | 4 | 0 | 0 | 4 |  |  |
| DI(데이터인프라) | `C000952` | DI-Cluster | 53 | 4 | 0 | 49 |  |  |
| DI(데이터인프라) | `C000956` | DI-kafka | 14 | 1 | 0 | 13 |  |  |
| DI(데이터인프라) | `C000962` | DI-s3upload | 2 | 0 | 0 | 2 |  |  |
| DI(데이터인프라) | `C001000` | DI-LogSentinel | 2 | 0 | 0 | 2 |  |  |
| DI(데이터인프라) | `C001041` | DI-mdproxy | 1 | 0 | 0 | 1 |  |  |
| DI(데이터인프라) | `C001148` | DI-NG | 66 | 0 | 0 | 66 |  |  |
| DI(데이터인프라) | `C001149` | DI-Rake | 4 | 0 | 0 | 4 |  |  |
| DI(데이터인프라) | `C001601` | DI-trino | 13 | 0 | 0 | 13 |  |  |
| DI(데이터인프라) | `C002384` | DI-proxy | 10 | 0 | 0 | 10 |  |  |
| DI(데이터인프라) | `C002467` | DI-Elastic | 13 | 0 | 0 | 13 |  |  |
| DI(데이터인프라) | `C002476` | DI-QueryCache | 10 | 0 | 0 | 10 |  |  |
| DI(데이터인프라) | `C002701` | DI-hive | 6 | 0 | 0 | 6 |  |  |
| DI(데이터인프라) | `C002838` | DI-Boat(k8s) | 16 | 1 | 0 | 15 |  |  |
| DI(데이터인프라) | `C002839` | DI-CMS-LOCK | 1 | 0 | 0 | 1 |  |  |
| DI(데이터인프라) | `C002897` | DI-AI | 2 | 0 | 0 | 2 |  |  |
| OCB | `C000946` | OCB-RECO | 2 | 0 | 0 | 2 |  |  |
| OCB | `C001053` | OCB-mobile | 2 | 1 | 0 | 1 |  |  |
| OCB | `C001054` | OCB-com | 6 | 5 | 0 | 1 |  |  |
| OCB | `C001055` | OCB-CMSadmin | 2 | 1 | 0 | 1 |  |  |
| OCB | `C001056` | OCB-성수 | 1 | 1 | 0 | 0 | {bg:#D4EDDA}🟢 완료 |  |
| OCB | `C001065` | OCB-OneIDPass | 4 | 0 | 0 | 4 |  |  |
| OCB | `C001068` | OCBpass | 18 | 9 | 0 | 9 |  |  |
| OCB | `C001070` | OCB-Sugar | 24 | 11 | 0 | 13 |  |  |
| OCB | `C001072` | OCB-WebView | 12 | 3 | 0 | 9 |  |  |
| OCB | `C001074` | OCB-게임Biz | 4 | 0 | 0 | 4 |  |  |
| OCB | `C001076` | OCB-이벤트마일리지 | 1 | 0 | 0 | 1 |  |  |
| OCB | `C001310` | OCB-IAM | 1 | 1 | 0 | 0 | {bg:#D4EDDA}🟢 완료 |  |
| OCB | `C001328` | OCB-참여적립 | 2 | 2 | 0 | 0 | {bg:#D4EDDA}🟢 완료 |  |
| OCB | `C001437` | OCB이벤트-AppEvt | 1 | 0 | 0 | 1 |  |  |
| OCB | `C001503` | OCB-모바일전단 | 1 | 0 | 0 | 1 |  |  |
| OCB | `C001509` | OCB-Locker | 11 | 0 | 0 | 11 |  |  |
| OCB | `C001527` | OCB이벤트-PoC | 3 | 2 | 0 | 1 |  |  |
| OCB | `C001611` | OCB-FDS | 1 | 0 | 0 | 1 |  |  |
| OCB | `C001737` | OCB-DeepLink | 1 | 1 | 0 | 0 | {bg:#D4EDDA}🟢 완료 |  |
| OCB | `C001738` | OCB-애드팝콘 | 2 | 2 | 0 | 0 | {bg:#D4EDDA}🟢 완료 |  |
| OCB | `C001743` | OCB-캐쉬백몰(적립) | 2 | 1 | 0 | 1 |  |  |
| OCB | `C001753` | OCB-부루마블 | 1 | 0 | 0 | 1 |  |  |
| OCB | `C001755` | OCB-KHub | 1 | 0 | 0 | 1 |  |  |
| OCB | `C001759` | OCB-쇼핑적립 | 2 | 0 | 0 | 2 |  |  |
| OCB | `C001839` | OCB-연말정산 | 1 | 1 | 0 | 0 | {bg:#D4EDDA}🟢 완료 |  |
| OCB | `C001881` | OCB-NFT | 12 | 6 | 0 | 6 |  |  |
| OCB | `C002289` | OCB-PAYUI(간편사용) | 7 | 5 | 0 | 2 |  |  |
| OCB | `C002388` | OCB-LoginUI(간편로그인) | 4 | 2 | 0 | 2 |  |  |
| OCB | `C002454` | OCB-AI쇼핑비서 | 2 | 0 | 0 | 2 |  |  |
| OCB | `C002466` | OCB-OMNI | 4 | 0 | 0 | 4 |  |  |
| OCB | `C002470` | OCB-맞고 | 3 | 0 | 0 | 3 |  |  |
| OCB | `C002651` | OCB-통장암호화 | 10 | 1 | 0 | 9 |  |  |
| OCB | `C002654` | OCB이벤트-Promotion | 6 | 2 | 0 | 4 |  |  |
| OCB | `C002849` | OCB-오글오글 | 4 | 4 | 0 | 0 | {bg:#D4EDDA}🟢 완료 |  |
| OCB | `C002850` | OKICK-서비스 | 7 | 6 | 0 | 1 |  |  |
| OCB | `C002858` | OCB-캐쉬백몰(front) | 1 | 1 | 0 | 0 | {bg:#D4EDDA}🟢 완료 |  |
| OCB | `C002885` | OCB-TM(보험) | 2 | 0 | 0 | 2 |  |  |
| OCB | `C002899` | OCB-쇼핑적립 | 15 | 0 | 0 | 15 |  |  |
| OCB | `C002913` | OCB-JOY | 3 | 2 | 0 | 1 |  |  |
| OCB | `C002915` | OKICK-컨텐츠 | 4 | 0 | 0 | 4 |  |  |
| OCB | `C002925` | OCB-복지포인트 | 3 | 1 | 0 | 2 |  |  |
| OCB | `C002929` | OCB-MINT | 2 | 0 | 0 | 2 |  |  |
| OCB | `C002930` | OCB-SugarSol | 3 | 2 | 0 | 1 |  |  |
| PICASO | `C001152` | PICASO | 1 | 0 | 0 | 1 |  |  |
| PICASO | `C001425` | PICASO | 2 | 0 | 0 | 2 |  |  |
| PICASO | `C001571` | PICASO-Mashup | 2 | 0 | 0 | 2 |  |  |
| PICASO | `C001764` | PICASO-IMC | 9 | 1 | 0 | 8 |  |  |
| PICASO | `C001767` | PICASO-BMS | 1 | 0 | 0 | 1 |  |  |
| Proxy | `C000954` | Proxy-기프티콘 | 6 | 0 | 0 | 6 |  |  |
| Proxy | `C001016` | Proxy-Syrup | 4 | 0 | 0 | 4 |  |  |
| Proxy | `C001524` | Proxy-DATA | 4 | 0 | 0 | 4 |  |  |
| Proxy | `C002520` | Proxy-OCB | 12 | 0 | 0 | 12 |  |  |
| Syrup | `C001176` | SyrupWallet-DBIF | 9 | 0 | 0 | 9 |  |  |
| Syrup | `C001177` | SyrupWallet-IOP | 11 | 0 | 0 | 11 |  |  |
| Syrup | `C001179` | SyrupWallet-Push | 10 | 0 | 0 | 10 |  |  |
| Syrup | `C001181` | SyrupWallet-APPIF | 9 | 0 | 0 | 9 |  |  |
| Syrup | `C001182` | SyrupWallet-MT | 9 | 0 | 0 | 9 |  |  |
| Syrup | `C001185` | SyrupWallet-Coupon | 5 | 0 | 0 | 5 |  |  |
| Syrup | `C001186` | SyrupWallet홈페이지 | 10 | 0 | 0 | 10 |  |  |
| Syrup | `C001198` | SyrupStore-IS | 13 | 0 | 0 | 13 |  |  |
| Syrup | `C001419` | SyrupWallet-Gateway | 10 | 0 | 0 | 10 |  |  |
| Syrup | `C001599` | SyrupStore-Auth | 6 | 0 | 0 | 6 |  |  |
| Syrup | `C002317` | SyrupWallet-ImageRR | 12 | 0 | 0 | 12 |  |  |
| Syrup | `C002818` | SyrupWallet-PFMS | 25 | 0 | 0 | 25 |  |  |
| Syrup | `C002866` | SyrupWallet-CIF | 16 | 0 | 0 | 16 |  |  |
| Syrup | `C002870` | Syrup-OZ | 1 | 0 | 0 | 1 |  |  |
| 광고플랫폼 | `C001330` | 광고리포팅(WebAR) | 2 | 0 | 0 | 2 |  |  |
| 광고플랫폼 | `C001650` | 광고플랫폼-PlanetAD | 3 | 0 | 0 | 3 |  |  |
| 광고플랫폼 | `C001894` | 광고플랫폼-PlanetAD | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C000935` | 데드코드분석-전금법 | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C000970` | IPMS | 4 | 0 | 0 | 4 |  |  |
| 미분류 | `C000995` | JARVIS | 12 | 1 | 0 | 11 |  |  |
| 미분류 | `C001187` | 마케팅플러스 | 14 | 0 | 0 | 14 |  |  |
| 미분류 | `C001194` | Proximity | 3 | 0 | 0 | 3 |  |  |
| 미분류 | `C001197` | IMC | 8 | 1 | 0 | 7 |  |  |
| 미분류 | `C001219` | 고객센터효율화 | 4 | 0 | 0 | 4 |  |  |
| 미분류 | `C001355` | 기프티콘-엔쿠폰 | 4 | 0 | 0 | 4 |  |  |
| 미분류 | `C001385` | T아카데미 | 3 | 0 | 0 | 3 |  |  |
| 미분류 | `C001391` | AI모멘트 | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C001429` | Proximity | 24 | 0 | 0 | 24 |  |  |
| 미분류 | `C001438` | 마이데이터-정보제공(MyDATA) | 18 | 0 | 0 | 18 |  |  |
| 미분류 | `C001516` | V컬러링-MarketPlace | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C001537` | Recopick-DIIF | 3 | 0 | 0 | 3 |  |  |
| 미분류 | `C001561` | O2O솔루션-이벤트GW | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C001604` | 문자매니저 | 3 | 0 | 0 | 3 |  |  |
| 미분류 | `C001667` | 통합쿠폰-비인증형 | 5 | 0 | 0 | 5 |  |  |
| 미분류 | `C001702` | DMP | 35 | 1 | 0 | 34 |  |  |
| 미분류 | `C001714` | T스마트세이프 | 8 | 0 | 0 | 8 |  |  |
| 미분류 | `C001717` | O2O솔루션-CLO | 10 | 0 | 0 | 10 |  |  |
| 미분류 | `C001746` | 데드코드분석 | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C001748` | LKICK-서비스 | 15 | 0 | 0 | 15 |  |  |
| 미분류 | `C001768` | OBIZSMS | 8 | 0 | 0 | 8 |  |  |
| 미분류 | `C001780` | PStore | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C001823` | DMP-비실명 | 21 | 0 | 0 | 21 |  |  |
| 미분류 | `C001855` | KHUB-PORTAL | 3 | 0 | 0 | 3 |  |  |
| 미분류 | `C001963` | 챗봇-고객센터이메일BE | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C002038` | DMP-실명 | 17 | 0 | 0 | 17 |  |  |
| 미분류 | `C002043` | 사내GPT | 4 | 0 | 0 | 4 |  |  |
| 미분류 | `C002309` | 러닝월드 | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C002327` | 기프티콘 | 12 | 0 | 0 | 12 |  |  |
| 미분류 | `C002354` |  | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C002400` | INFRA-ITSM | 3 | 0 | 0 | 3 |  |  |
| 미분류 | `C002401` | INFRA-opsdb | 4 | 0 | 0 | 4 |  |  |
| 미분류 | `C002452` | 동탄성심병원 | 14 | 0 | 0 | 14 |  |  |
| 미분류 | `C002455` | Recopick-adm | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C002456` | Recopick-batch | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C002462` | LOGX | 10 | 0 | 0 | 10 |  |  |
| 미분류 | `C002464` | CI빌드관리 | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C002521` | SKICK-서비스 | 6 | 0 | 0 | 6 |  |  |
| 미분류 | `C002527` | 폰세이프상담AP | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C002547` | APPMON | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C002565` | SKT-TIIS | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C002602` | PCONA | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C002664` | 금융소비자포털 | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C002766` | 개발환경포털 | 9 | 0 | 0 | 9 |  |  |
| 미분류 | `C002772` | BizChat | 23 | 0 | 0 | 23 |  |  |
| 미분류 | `C002779` | VAS신규-스타칩2 담당자 | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C002788` | AIPLTM | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C002800` | T안심콜 | 10 | 5 | 0 | 5 |  |  |
| 미분류 | `C002803` | T통화매니저 | 5 | 0 | 0 | 5 |  |  |
| 미분류 | `C002804` | VASGW | 3 | 0 | 0 | 3 |  |  |
| 미분류 | `C002811` | TUMS(통합뮤직) | 3 | 0 | 0 | 3 |  |  |
| 미분류 | `C002825` | AIR | 9 | 0 | 0 | 9 |  |  |
| 미분류 | `C002848` | V컬러링 | 15 | 0 | 0 | 15 |  |  |
| 미분류 | `C002865` | 마케팅플러스-Event | 1 | 0 | 0 | 1 |  |  |
| 미분류 | `C002887` | 벨ASP | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C002907` | 오라방-livemoa | 4 | 0 | 0 | 4 |  |  |
| 미분류 | `C002908` | TALKS | 4 | 0 | 0 | 4 |  |  |
| 미분류 | `C002910` | CONBT | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C002911` | PlanetM | 3 | 0 | 0 | 3 |  |  |
| 미분류 | `C002912` | BCHAT-API | 6 | 0 | 0 | 6 |  |  |
| 미분류 | `C002923` | 오픈리워드솔루션 | 4 | 0 | 0 | 4 |  |  |
| 미분류 | `C002924` | INSIGHTLENS | 2 | 0 | 0 | 2 |  |  |
| 미분류 | `C002926` | OUTLINK-RT | 4 | 0 | 0 | 4 |  |  |
| 미분류 | `C002927` | KICK11-서비스 | 6 | 0 | 0 | 6 |  |  |
| 미분류 | `C999999` | 개발환경포털 | 3 | 0 | 0 | 3 |  |  |
| 보안 | `C001132` | 보안-보안진단 | 4 | 0 | 0 | 4 |  |  |
| 인프라운영 | `C001403` | MGMT-ME | 2 | 0 | 0 | 2 |  |  |
| 인프라운영 | `C001545` | MGMT-ME | 3 | 0 | 0 | 3 |  |  |
| {bg:#E8E8E8}BI | {bg:#E8E8E8}`C001043` | {bg:#E8E8E8}BI서비스-OGGSYW | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}BI | {bg:#E8E8E8}`C001044` | {bg:#E8E8E8}BI서비스-SODAR | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}BI | {bg:#E8E8E8}`C001600` | {bg:#E8E8E8}BI서비스-DQM | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}BI | {bg:#E8E8E8}`C001613` | {bg:#E8E8E8}BI서비스-SSBI | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}BI | {bg:#E8E8E8}`C001852` | {bg:#E8E8E8}BI서비스-DQmeta | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}BI | {bg:#E8E8E8}`C001853` | {bg:#E8E8E8}BI서비스-정보제공 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}BI | {bg:#E8E8E8}`C002325` | {bg:#E8E8E8}BI서비스-데이터가명화 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}BI | {bg:#E8E8E8}`C002477` | {bg:#E8E8E8}BI서비스-OGGOCB | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}DI(데이터인프라) | {bg:#E8E8E8}`C000957` | {bg:#E8E8E8}DI-Impala | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}DI(데이터인프라) | {bg:#E8E8E8}`C001416` | {bg:#E8E8E8}DI-AI | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}DI(데이터인프라) | {bg:#E8E8E8}`C001841` | {bg:#E8E8E8}DI-governor | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}DI(데이터인프라) | {bg:#E8E8E8}`C002405` | {bg:#E8E8E8}DI-Druid | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}OCB | {bg:#E8E8E8}`C001699` | {bg:#E8E8E8}OCB-게임PnP | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}OCB | {bg:#E8E8E8}`C002056` | {bg:#E8E8E8}OCB-RECO | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}OCB | {bg:#E8E8E8}`C002465` | {bg:#E8E8E8}OCB-공통DB | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}OCB | {bg:#E8E8E8}`C002519` | {bg:#E8E8E8}OCB-OMNI | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}OCB | {bg:#E8E8E8}`C002652` | {bg:#E8E8E8}OCB-TM(보험)-FTS | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}OCB | {bg:#E8E8E8}`C002852` | {bg:#E8E8E8}OCB-KHub-GW | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}Syrup | {bg:#E8E8E8}`C001193` | {bg:#E8E8E8}SyrupWallet-E2E | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}Syrup | {bg:#E8E8E8}`C002671` | {bg:#E8E8E8}SyrupWallet-FIDO | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}Syrup | {bg:#E8E8E8}`C002917` | {bg:#E8E8E8}SyrupWallet-ImageRR | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}Syrup | {bg:#E8E8E8}`C002919` | {bg:#E8E8E8}SyrupWallet-Crypto | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}Syrup | {bg:#E8E8E8}`C002920` | {bg:#E8E8E8}SyrupWallet-Memcached | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}광고플랫폼 | {bg:#E8E8E8}`C002741` | {bg:#E8E8E8}광고플랫폼-CICD | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}광고플랫폼 | {bg:#E8E8E8}`C002933` | {bg:#E8E8E8}광고플랫폼-DOOH | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C000987` | {bg:#E8E8E8}ADSSO | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C000988` | {bg:#E8E8E8}계정관리 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C000990` | {bg:#E8E8E8}Wiki | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C000998` | {bg:#E8E8E8}Office365 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001143` | {bg:#E8E8E8}QA-로드런너-SKP | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001166` | {bg:#E8E8E8}Blackduck(OSS) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001206` | {bg:#E8E8E8}연말정산 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001212` | {bg:#E8E8E8}Crowd | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001321` | {bg:#E8E8E8}Rbinsight | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001428` | {bg:#E8E8E8}채용관리시스템 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001433` | {bg:#E8E8E8}ARHIS | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001517` | {bg:#E8E8E8}IP마당 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001668` | {bg:#E8E8E8}통합쿠폰-Delivery | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001783` | {bg:#E8E8E8}전자결재문서 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001785` | {bg:#E8E8E8}휴양소시스템 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001786` | {bg:#E8E8E8}EIMS | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001802` | {bg:#E8E8E8}Arena | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001808` | {bg:#E8E8E8}출입관리 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001809` | {bg:#E8E8E8}판교-기타 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001829` | {bg:#E8E8E8}통합검색시스템 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001846` | {bg:#E8E8E8}DevOps-Docker | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001860` | {bg:#E8E8E8}메일 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001862` | {bg:#E8E8E8}ERP-EP | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001863` | {bg:#E8E8E8}PNET | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001865` | {bg:#E8E8E8}EAI | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001866` | {bg:#E8E8E8}기업홈페이지 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001871` | {bg:#E8E8E8}S-VDI | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001872` | {bg:#E8E8E8}OA-VDI | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001875` | {bg:#E8E8E8}경영지원기타 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001887` | {bg:#E8E8E8}전자문서이관 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C001910` | {bg:#E8E8E8}전자증빙 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002061` | {bg:#E8E8E8}사내고객지원 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002301` | {bg:#E8E8E8}Pnet암호초기화시스템 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002356` | {bg:#E8E8E8}52시간근무환경 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002395` | {bg:#E8E8E8}Etax | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002458` | {bg:#E8E8E8}Bitbucket | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002502` | {bg:#E8E8E8}IBAS | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002506` | {bg:#E8E8E8}UXINFRA | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002511` | {bg:#E8E8E8}PCSW관리시스템 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002518` | {bg:#E8E8E8}CBH | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002522` | {bg:#E8E8E8}마이데이터-정보제공(MyDATA) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002541` | {bg:#E8E8E8}RBSpace | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002549` | {bg:#E8E8E8}Rbinsight-DIboat | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002627` | {bg:#E8E8E8}ERP컨텐츠 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002663` | {bg:#E8E8E8}ERP파일서버 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002693` | {bg:#E8E8E8}DEP | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002708` | {bg:#E8E8E8}Jira-Wiki | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002771` | {bg:#E8E8E8}APIGateway | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002787` | {bg:#E8E8E8}QA품질관리시스템 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002794` | {bg:#E8E8E8}DCMF(디지털컨텐츠관리프레임웍) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002797` | {bg:#E8E8E8}NGcP(차세대컨버전스플랫폼) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002798` | {bg:#E8E8E8}PMH(플랫폼메시징허브) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002799` | {bg:#E8E8E8}T-ARS | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002801` | {bg:#E8E8E8}T컬러링검색 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002812` | {bg:#E8E8E8}T메모링(TMR) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002817` | {bg:#E8E8E8}VDI | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002819` | {bg:#E8E8E8}AIR | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002820` | {bg:#E8E8E8}OpenStack-MGMT | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002823` | {bg:#E8E8E8}AWS-기타 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002851` | {bg:#E8E8E8}챗봇솔루션 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002861` | {bg:#E8E8E8}윤리포털 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002862` | {bg:#E8E8E8}법인카드정산 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002863` | {bg:#E8E8E8}사보서비스 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002891` | {bg:#E8E8E8}단말대여시스템 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002892` | {bg:#E8E8E8}APE-ONE백신서버(PC용도) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002895` | {bg:#E8E8E8}오사라마켓 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002896` | {bg:#E8E8E8}DMP-MMP | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002898` | {bg:#E8E8E8}OBIZSMS | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002900` | {bg:#E8E8E8}컬러링플러스 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002902` | {bg:#E8E8E8}FVDI-MGMT | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002904` | {bg:#E8E8E8}OA-Crowd | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002906` | {bg:#E8E8E8}NXmile-v2 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}미분류 | {bg:#E8E8E8}`C002928` | {bg:#E8E8E8}AIPF | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C001731` | {bg:#E8E8E8}보안-EDR | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C001794` | {bg:#E8E8E8}보안-방화벽정책분석 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C001870` | {bg:#E8E8E8}보안운영 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C001873` | {bg:#E8E8E8}보안-DB접근제어 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C001886` | {bg:#E8E8E8}보안관제 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C001911` | {bg:#E8E8E8}보안-서버접근제어 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C001915` | {bg:#E8E8E8}보안기타 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C001921` | {bg:#E8E8E8}보안-망연계시스템 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C001925` | {bg:#E8E8E8}보안-서버설정진단 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C002609` | {bg:#E8E8E8}보안-OA환경 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C002843` | {bg:#E8E8E8}보안-보안진단 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C002888` | {bg:#E8E8E8}보안-MGMT(OA) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C002893` | {bg:#E8E8E8}보안-문서보안-신서버 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}보안 | {bg:#E8E8E8}`C002901` | {bg:#E8E8E8}보안포탈개선 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001012` | {bg:#E8E8E8}MGMT(성수)-SE | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001028` | {bg:#E8E8E8}MGMT-DNS | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001029` | {bg:#E8E8E8}MGMT-DB | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001030` | {bg:#E8E8E8}MGMT(일산)-NW | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001033` | {bg:#E8E8E8}MGMT(일산)-SE | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001034` | {bg:#E8E8E8}MGMT(일산)-Storage | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001035` | {bg:#E8E8E8}MGMT-백업 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001322` | {bg:#E8E8E8}MGMT-infratool | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001784` | {bg:#E8E8E8}MGMT(OA)-Network | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001787` | {bg:#E8E8E8}MGMT(OA)-Storage | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C001874` | {bg:#E8E8E8}MGMT(OA)-VMware(VCS) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C002379` | {bg:#E8E8E8}MGMT-VMware(VCS) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C002392` | {bg:#E8E8E8}MGMT(OA)-SE | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C002416` | {bg:#E8E8E8}MGMT-WIN | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C002417` | {bg:#E8E8E8}MGMT-PMAILTX | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C002783` | {bg:#E8E8E8}MGMT(성수)-NW | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C002784` | {bg:#E8E8E8}MGMT(성수)-Storage | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C002785` | {bg:#E8E8E8}MGMT-Nutanix(판교) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C002884` | {bg:#E8E8E8}MGMT-장애관리IMC | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}인프라운영 | {bg:#E8E8E8}`C002889` | {bg:#E8E8E8}MGMT(OA)-Server | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}정보료과금 | {bg:#E8E8E8}`C002793` | {bg:#E8E8E8}정보료과금 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}정보료과금 | {bg:#E8E8E8}`C002872` | {bg:#E8E8E8}정보료과금-과금처리(통합IF) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}정보료과금 | {bg:#E8E8E8}`C002873` | {bg:#E8E8E8}정보료과금-과금처리(실시간) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}정보료과금 | {bg:#E8E8E8}`C002874` | {bg:#E8E8E8}정보료과금-과금처리(후불IF) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}정보료과금 | {bg:#E8E8E8}`C002876` | {bg:#E8E8E8}정보료과금-과금처리(MMS) | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |
| {bg:#E8E8E8}정보료과금 | {bg:#E8E8E8}`C002877` | {bg:#E8E8E8}정보료과금-Billing통계기능 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8}0 | {bg:#E8E8E8} | {bg:#E8E8E8}레포 미확인 |

## 2. 레포별 상세 진단현황 (전체 1062건)

:::expand 레포별 상세 진단현황 (전체 1062건, 클릭하여 펼치기)

| 상위 서비스군 | 시스템코드 | 레포 | INJ | XSS | FILE | DATA | 최근스캔일 |
|---|---|---|---|---|---|---|---|
| DI(데이터인프라) | `C000952` | `OCBNFT/ocb-nft-admin-front` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| DI(데이터인프라) | `C000952` | `OCBNFT/ocb-nft-backend` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| DI(데이터인프라) | `C000952` | `OCBNFT/ocb-nft-batch` | ✅ | ✅ | ✅ | ✅ | 2026-07-24 |
| DI(데이터인프라) | `C000952` | `OCBNFT/ocb-nft-fingerlabs` | ✅ | ✅ | ✅ | ✅ | 2026-07-24 |
| DI(데이터인프라) | `C000956` | `OCBNFT/ocb-nft-backend` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| DI(데이터인프라) | `C002838` | `OCBNFT/ocb-nft-backend` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| OCB | `C001053` | `OEP/cms_resource` | ✅ | ✅ | ✅ | ✅ | 2026-07-01 |
| OCB | `C001054` | `OCBWEBVIEW/ocbws-frontend` | ✅ | ✅ | ✅ | ✅ | 2026-05-06 |
| OCB | `C001054` | `OCBWEBVIEW/ocbws-nxmile-gateway` | ✅ | ✅ | ✅ | ✅ | 2026-05-06 |
| OCB | `C001054` | `OCBWEBVIEW/ocbws-web-api` | ✅ | ✅ | ✅ | ✅ | 2026-05-06 |
| OCB | `C001054` | `OSA/displayadmin_server` | ✅ | ✅ | ✅ | ✅ | 2026-07-27 |
| OCB | `C001054` | `OSA/displayadmin_ui` | ✅ | ✅ | ✅ | ✅ | 2026-07-27 |
| OCB | `C001055` | `OEP/cms_resource` | ✅ | ✅ | ✅ | ✅ | 2026-07-01 |
| OCB | `C001056` | `OCBSUGAR/fail-info` | ✅ | ✅ | ✅ | ✅ | 2026-06-23 |
| OCB | `C001068` | `OCBNFT/ocb-nft-backend` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| OCB | `C001068` | `OCBNFT/ocb-nft-batch` | ✅ | ✅ | ✅ | ✅ | 2026-07-24 |
| OCB | `C001068` | `OCBNFT/ocb-nft-homepage` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| OCB | `C001068` | `OCBPASS/ocbpass-11st` | ✅ | ✅ | ✅ | ✅ | 2026-08-04 |
| OCB | `C001068` | `OCBPASS/ocbpass-admin` | ✅ | ✅ | ✅ | ✅ | 2026-08-06 |
| OCB | `C001068` | `OCBPASS/ocbpass-app` | ✅ | ✅ | ✅ | ✅ | 2026-08-06 |
| OCB | `C001068` | `OCBPASS/ocbpass-batch` | ✅ | ✅ | ✅ | ✅ | 2026-08-11 |
| OCB | `C001068` | `OCBPASS/ocbpass-inside` | ✅ | ✅ | ✅ | ✅ | 2026-08-11 |
| OCB | `C001068` | `OCBPASS/ocbpass-newpg` | ✅ | ✅ | ✅ | ✅ | 2026-08-12 |
| OCB | `C001070` | `OCBNFT/ocb-nft-backend` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| OCB | `C001070` | `OCBNFT/ocb-nft-fingerlabs` | ✅ | ✅ | ✅ | ✅ | 2026-07-24 |
| OCB | `C001070` | `OCBSUGAR/bms_admin` | ✅ | ✅ | ✅ | ✅ | 2026-06-17 |
| OCB | `C001070` | `OCBSUGAR/ocb-epm` | ✅ | ✅ | ✅ | ✅ | 2026-06-01 |
| OCB | `C001070` | `OCBSUGAR/ocb-soi-appweb` | ✅ | ✅ | ✅ | ✅ | 2026-06-15 |
| OCB | `C001070` | `OCBSUGAR/ocb-sugar` | ✅ | ✅ | ✅ | ✅ | 2026-05-12 |
| OCB | `C001070` | `OCBSUGAR/soi-event-consumer` | ✅ | ✅ | ✅ | ✅ | 2026-06-02 |
| OCB | `C001070` | `OCBSUGAR/sugar-admin-worker` | ✅ | ✅ | ✅ | ✅ | 2026-06-02 |
| OCB | `C001070` | `OCBSUGAR/trwas` | ✅ | ✅ | ✅ | ✅ | 2026-06-03 |
| OCB | `C001070` | `OCBWEBVIEW/ocb-admin-frontend` | ✅ | ✅ | ✅ | ✅ | 2026-05-21 |
| OCB | `C001070` | `OCBWEBVIEW/ocb-webview-reward-api` | ✅ | ✅ | ✅ | ✅ | 2026-05-06 |
| OCB | `C001072` | `OCBWEBVIEW/ocb-service-frontend` | ✅ | ✅ | ✅ | ✅ | 2026-06-24 |
| OCB | `C001072` | `OCBWEBVIEW/ocb-webview-api` | ✅ | ✅ | ✅ | ✅ | 2026-05-06 |
| OCB | `C001072` | `OCBWEBVIEW/ocb-webview-frontend` | ✅ | ✅ | ✅ | ✅ | 2026-05-06 |
| OCB | `C001310` | `OCBSUGAR/ocb-iam` | ✅ | ✅ | ✅ | ✅ | 2026-06-01 |
| OCB | `C001328` | `OCBRWD/rwd_adm` | ✅ | ✅ | ✅ | ✅ | 2026-07-15 |
| OCB | `C001328` | `OCBRWD/rwd_front` | ✅ | ✅ | ✅ | ✅ | 2026-07-15 |
| OCB | `C001527` | `OB/ob-backend` | ✅ | ✅ | ✅ | ✅ | 2026-07-23 |
| OCB | `C001527` | `OEP/cms_resource` | ✅ | ✅ | ✅ | ✅ | 2026-07-01 |
| OCB | `C001737` | `OCBWEBVIEW/ocb-webview-deeplink` | ✅ | ✅ | ✅ | ✅ | 2026-05-06 |
| OCB | `C001738` | `OCBE/ocb-event-front` | ✅ | ✅ | ✅ | ✅ | 2026-05-27 |
| OCB | `C001738` | `OCBE/ocb-event-server` | ✅ | ✅ | ✅ | ✅ | 2026-05-27 |
| OCB | `C001743` | `OB/cashbagmall` | ✅ | ✅ | ✅ | ✅ | 2026-07-14 |
| OCB | `C001839` | `OEP/yetax_resource` | ✅ | ✅ | ✅ | ✅ | 2026-07-13 |
| OCB | `C001881` | `OCBNFT/ocb-nft-admin-front` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| OCB | `C001881` | `OCBNFT/ocb-nft-backend` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| OCB | `C001881` | `OCBNFT/ocb-nft-fingerlabs` | ✅ | ✅ | ✅ | ✅ | 2026-07-24 |
| OCB | `C001881` | `OCBNFT/ocb-nft-frontend` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| OCB | `C001881` | `OCBNFT/ocb-nft-homepage` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| OCB | `C001881` | `OCBWEBVIEW/ocb-webview-reward-api` | ✅ | ✅ | ✅ | ✅ | 2026-05-06 |
| OCB | `C002289` | `OCBPU/ocbpayui-front-api` | ✅ | ✅ | ✅ | ✅ | 2026-08-10 |
| OCB | `C002289` | `OCBPU/ocbpayui-frontend-admin` | ✅ | ✅ | ✅ | ✅ | 2026-08-10 |
| OCB | `C002289` | `OCBPU/ocbpayui-frontend-web` | ✅ | ✅ | ✅ | ✅ | 2026-08-10 |
| OCB | `C002289` | `OCBPU/ocbpayui-merchant-api` | ✅ | ✅ | ✅ | ✅ | 2026-08-10 |
| OCB | `C002289` | `OCBPU/ocbpayui-nxmile-grpc` | ✅ | ✅ | ✅ | ✅ | 2026-08-05 |
| OCB | `C002388` | `OCBPU/ocbpayui-batch` | ✅ | ✅ | ✅ | ✅ | 2026-08-04 |
| OCB | `C002388` | `OCBPU/ocbpayui-frontend-web` | ✅ | ✅ | ✅ | ✅ | 2026-08-10 |
| OCB | `C002651` | `OCBSUGAR/ocb_passbook_enc` | ✅ | ✅ | ✅ | ✅ | 2026-06-03 |
| OCB | `C002654` | `OEP/cms_resource` | ✅ | ✅ | ✅ | ✅ | 2026-07-01 |
| OCB | `C002654` | `OEP/event_resource` | ✅ | ✅ | ✅ | ✅ | 2026-06-30 |
| OCB | `C002849` | `OCBWEBVIEW/ocb-community-api` | ✅ | ✅ | ✅ | ✅ | 2026-06-30 |
| OCB | `C002849` | `OCBWEBVIEW/ocb-community-ssr` | ✅ | ✅ | ✅ | ✅ | 2026-06-30 |
| OCB | `C002849` | `OCBWEBVIEW/ocb-ogeul-admin-frontend` | ✅ | ✅ | ✅ | ✅ | 2026-06-30 |
| OCB | `C002849` | `OCBWEBVIEW/ocb-webview-admin-api` | ✅ | ✅ | ✅ | ✅ | 2026-06-30 |
| OCB | `C002850` | `OKICK/okick-event-batch-server` | ✅ | ✅ | ✅ | ✅ | 2026-07-27 |
| OCB | `C002850` | `OKICK/okick-event-server` | ✅ | ✅ | ✅ | ✅ | 2026-07-27 |
| OCB | `C002850` | `OKICK/okick-front` | ✅ | ✅ | ✅ | ✅ | 2026-07-27 |
| OCB | `C002850` | `OKICK/okick-reward-batch-server` | ✅ | ✅ | ✅ | ✅ | 2026-07-27 |
| OCB | `C002850` | `OKICK/okick-reward-front` | ✅ | ✅ | ✅ | ✅ | 2026-07-27 |
| OCB | `C002850` | `OKICK/okick-reward-server` | ✅ | ✅ | ✅ | ✅ | 2026-07-27 |
| OCB | `C002858` | `OB/cashbagmall` | ✅ | ✅ | ✅ | ✅ | 2026-07-14 |
| OCB | `C002913` | `OCBWEBVIEW/ocb-joy-api` | ✅ | ✅ | ✅ | ✅ | 2026-04-30 |
| OCB | `C002913` | `OCBWEBVIEW/ocb-joy-frontend` | ✅ | ✅ | ✅ | ✅ | 2026-05-04 |
| OCB | `C002925` | `OCBWEBVIEW/ocb-webview-frontend` | ✅ | ✅ | ✅ | ✅ | 2026-05-06 |
| OCB | `C002930` | `OCBSUGAR/ocb-wp-api` | ✅ | ✅ | ✅ | ✅ | 2026-06-01 |
| OCB | `C002930` | `OCBSUGAR/ocb-wp-frontend` | ✅ | ✅ | ✅ | ✅ | 2026-06-24 |
| PICASO | `C001764` | `PIC/batch-script` | ✅ | ✅ | ✅ | ✅ | 2026-06-29 |
| 미분류 | `C000995` | `OCBNFT/ocb-nft-backend` | ✅ | ✅ | ✅ | ✅ | 2026-08-03 |
| 미분류 | `C001197` | `PIC/batch-script` | ✅ | ✅ | ✅ | ✅ | 2026-06-29 |
| 미분류 | `C001702` | `OCBPASS/ocbpg` | ✅ | ✅ | ✅ | ✅ | 2026-08-10 |
| 미분류 | `C002800` | `TSAFE/portalwas_monitoring` | ✅ | ✅ | ✅ | ✅ | 2026-05-28 |
| 미분류 | `C002800` | `TSAFE/portalwas_tworld` | ✅ | ✅ | ✅ | ✅ | 2026-05-20 |
| 미분류 | `C002800` | `TSAFE/restwas_deamon_initqueue` | ✅ | ✅ | ✅ | ✅ | 2026-05-28 |
| 미분류 | `C002800` | `TSAFE/restwas_safenumber2.5` | ✅ | ✅ | ✅ | ✅ | 2026-05-20 |
| 미분류 | `C002800` | `TSAFE/smswas_sms` | ✅ | ✅ | ✅ | ✅ | 2026-05-28 |
| BI | `C001302` | `VOYAG/voyager` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001302` | `VOYAG/voyager_kid` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001706` | `AANP/analog-python` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001706` | `AANP/analog-web` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001706` | `AANP/monitoring-status-update` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001706` | `DEP/dep-back` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001706` | `JVS_1/pds_jarvis_dashboard` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `AANP/zenia` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `BI/airflow_bi_custpfdb` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `BI/airflow_bi_ocb` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `BI/airflow_bi_proximity` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `BI/airflow_bi_syrupstore` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `BI/airflow_bi_syrupwallet` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `BIG-QUICK/quick-hive-udf` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `DEUDF/skpde-hive-udf` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `OCBBI/ocb_app_spark` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `OCBBI/ocb_bi_java` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `PROXIBI/oozie-product` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `SHELL/data-lifecycle` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `TER/t2a` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001778` | `XL/evs_skp` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001854` | `VOYAG/ncbi-admin` | ❌ | ❌ | ❌ | ❌ | — |
| BI | `C001854` | `VOYAG/ncbi-api` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000950` | `DI/gringotts-cron` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000950` | `DI/gringotts-was` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000950` | `DI/gringotts-web` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000950` | `DPT_1/galleon` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `ADS-DA/di-airflow-k8s` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `BI/airflow_bi_custpfdb` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `BI/airflow_bi_ictfhub` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `BI/airflow_bi_ocb` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `BI/airflow_bi_proximity` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `BI/airflow_bi_syrupstore` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `BI/airflow_bi_syrupwallet` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `BI/airflow_di_bi_evs_skp` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `BI/airflow_di_bi_test` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `BI/airflow_di_bi_utils` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/chat-dic-front` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/cms-airflow` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/di-airflow-dags` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/di-airflow-packages` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/di-jdk` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/ding-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/ictfamily_crosscheck` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/k8s-app-template` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/mlflow-api` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/mlflow-tracker` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/mlworks-install` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/mlworks-schedular` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/nginx-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/oggreapi` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/oozie-5.2.1` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/probe-airflow-batch` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/probe-web` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/qcpy` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/querycache-oozie` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/querycache2` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/rake` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/rangerbox-cron` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/rangerbox-was` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/rangerbox-web` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/router` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/scrooge` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/timebomb` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DI/trinoadmin-web` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DIT/dit` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DMP/dmp_column_search_di_airflow` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DMP/dmp_di_airflow` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DMP/dmp_di_airflow_export` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DMP/dmp_di_airflow_temp` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DMP/dmp_di_airflow_utils` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DMP/dmp_trait_rule_engine_v4` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `DMP/segment-engine` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `OCBNFT/ocb-nft-script` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `STSE/lake` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000952` | `SVCENG/helm-charts` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/hive-admin` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/hive-airlock-manager` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/hive-audit-hook` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/hive-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/kafka_script` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/logagent` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/logagent-keeper` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/querycache2` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/router` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/router-connect` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DI/router-front` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `DPT_1/querycache` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000956` | `OCBNFT/ocb-nft-script` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000962` | `DI/blacksmith` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C000962` | `DI/dic-distcp` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001000` | `DI/jdbc-tester` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001000` | `STSE/sentinel` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001041` | `DI/mdproxy-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/airflow` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/batch-system` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/blacksmith` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/burrowtoelasticsearch` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/chat-dic-iceberg` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/checkmate-java` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/dataexportapi` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/dataflow` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/di-airflow-packages` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/di-erlang` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/di-findclass` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/di-gen-tables` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/di-jdk` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/di-kermit` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/di-rabbitmq-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/di-shell-utils` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/di-tmpl-codec` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/di-utils` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/dic_script` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/drop_the_bit` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/flink-deploy` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/governor` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/hadoop-3.3.6-rc1` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/hdmin` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/hive-admin` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/hive-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/hivemeta-coredata` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/install-cert` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/jdbc-tester` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/kiki` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/kyuubi-client-test` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/kyuubi-deploy` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/medic` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/mesh` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/meta-gov` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/monitoring-alerts` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/nginx-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/oggreapi` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/probe` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/probe-was` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/qcshell-conf` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/querycache-demo` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/querycache2` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/rake-report` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/rangerbox-cron` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/rangerbox-was` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/recopick-stream2` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/router` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/router-connect` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/router-hive-processor` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/router-stream-processor` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/router-stream-vector` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/skt-checker` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/skybridge-airflow-ict-batch` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/spark` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/spark-ranger` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/sqoop-deploy` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/trino-dummy` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/trinoadmin-was` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/udf-di_string` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DI/zookeeper-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DPT_1/galleon` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DPT_1/medic-dataproc` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DPT_1/medic-web` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DPT_1/querycache` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001148` | `DPT_1/sentrybox-open` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001149` | `DI/new-rake-javascript` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001149` | `DI/rake` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001149` | `DI/rake-server-nginx` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001149` | `STSE/lake` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/di-erlang` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/di-ik-bin` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/di-rdbms-metrics` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/di-shell-utils` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/di-utils` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/impala-ct` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/impala-kudu` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/mongodb-conf` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/presto-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/querycache2` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/redis-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/trino-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C001601` | `DI/trino-monitor` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002384` | `DI/di-jdk` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002384` | `DI/di-shell-utils` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002384` | `DI/install-cert` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002384` | `DI/jdbc-tester` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002384` | `DI/node-proxy` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002384` | `DI/proxy-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002384` | `DI/querycache-conf` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002384` | `DI/querycache-conf.fdic` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002384` | `DI/querycache2` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002384` | `DPT_1/querycache` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/di-findclass` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/di-jdk` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/di-rdbms-metrics` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/di-utils` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/elasticsearchtest` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/impala-kudu` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/impala-kudu-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/jdbc-tester` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/mongodb-conf` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/presto-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/trino-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/trino-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002467` | `DI/trino-monitor` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002476` | `DI/di-jdk` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002476` | `DI/di-utils` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002476` | `DI/jdbc-tester` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002476` | `DI/mcp-qc` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002476` | `DI/proxy-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002476` | `DI/querycache-conf` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002476` | `DI/querycache-conf.fdic` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002476` | `DI/querycache2` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002476` | `DI/redis-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002476` | `DPT_1/querycache` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002701` | `DI/hive-admin` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002701` | `DI/hive-airlock-manager` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002701` | `DI/hive-audit-hook` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002701` | `DI/hive-configs` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002701` | `DI/querycache2` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002701` | `DPT_1/querycache` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/boat-jars` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/di-airflow` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/di-airflow-dags` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/di-airflow-packages` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/di-hadoop` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/hadoop-jmx-exporter` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/helmet-sb` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/k8s-node-default` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/llama-api` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/llama-server-img` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/pythonalt` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DI/querycache2` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `DPT_1/querycache` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `OCBNFT/ocb-nft-script` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002838` | `VAS/starchip_creator` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002839` | `DI/cms` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002897` | `DI/chat-dic-front` | ❌ | ❌ | ❌ | ❌ | — |
| DI(데이터인프라) | `C002897` | `DI/oozie2airflow-assist` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C000946` | `TENXTFSYN/ocb-reco-backend` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C000946` | `TENXTFSYN/ocb-reco-ranker` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001053` | `OC/ocb_module` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001054` | `OC/ocb_module` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001055` | `OC/ocb_module` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001065` | `ONEIDPASS/oip_admin` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001065` | `ONEIDPASS/oip_api` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001065` | `ONEIDPASS/oip_batch` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001065` | `ONEIDPASS/oip_front` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001068` | `OCBNFT/ocb-nft-script` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001068` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001068` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001068` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001068` | `SW/gw_out` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001068` | `SW/gw_out_homeplus` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001068` | `VAS/starchip2-creator-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001068` | `VAS/starchip2-user-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001068` | `VAS/starchip_admin` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `AI/ocb-api-with-python` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `DI/rake` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `GWS/gws-point-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `GWS/oki-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `OCBNFT/ocb-nft-script` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `OCB_BACK_END/nxmilegatewayfortmambership` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `OCB_BACK_END/ocb-push` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `OE/ocb-appevt` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `STSE/lake` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `SW/gw_out` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001070` | `VAS/starchip_admin` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001072` | `DMP/dmp-open-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001072` | `DMP/dmp-script` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001072` | `GWS/gws-admin-be-api` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001072` | `GWS/gws-admin-be-batch` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001072` | `GWS/gws-admin-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001072` | `GWS/gws-point-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001072` | `GWS/oki-admin-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001072` | `GWS/oki-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001072` | `OCB_BACK_END/ocb-webview` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001074` | `MKTIS/ocb_marketing_is` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001074` | `OCB-THP/ocb_fun_real` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001074` | `OCB-THP/ocb_game_biz` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001074` | `OCB-THP/ocb_game_biz_admin` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001076` | `EVENTPOINT/eventpoint` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001437` | `OE/ocb-appevt` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001503` | `LEAFLET/newleafletsystem` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `OL/locker-api-maintenance` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `OL/locker-api-web-nginx-conf` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `OL/locker-frontend-admin` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `OL/locker-gwout-web` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `OL/locker-push` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `OL/locker-server` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `OL/locker-vision` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `OL/locker-was-deploy` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `OL/locker-webview` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `OL/locker-webview-front` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001509` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001527` | `OB/front_resource` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001611` | `OCB_BACK_END/ocbfds` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001743` | `OCB_BACK_END/ocb-cashbag-mall` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001753` | `OCB-THP/ocb_game_bluemarble` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001755` | `OCBBI/pandora` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001759` | `HGV/skhgv-hgv-pub-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001759` | `HGV/skhgv-hhs-pub-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001881` | `DI/dataflow` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001881` | `DI/helm-wrapper-fork` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001881` | `DI/helm3` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001881` | `DI/helmetapi` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001881` | `OCBNFT/ocb-nft-script` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C001881` | `SVCENG/helm-charts` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002289` | `MEC/me_conf` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002289` | `OCBPP/ocb_payment_platform` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002388` | `OCBLU/ocbloginui-front-api` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002388` | `OCBLU/ocbloginui-partner-api` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002454` | `AI/ocb-api-with-python` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002454` | `AI/ocb-web-integration` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002466` | `OTH/homeshopping` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002466` | `OTH/trend-ad` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002466` | `OTH/trend-cms` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002466` | `OTH/trendissue` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002470` | `OCB-THP/ocb_game_biz_matgo` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002470` | `OCB-THP/ocb_game_biz_matgo_php_real` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002470` | `OCB-THP/ocb_game_biz_matgo_server` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002651` | `GWS/gws-admin-be-api` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002651` | `GWS/gws-promotion-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002651` | `GWS/gws-promotion-consumer-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002651` | `GWS/oki-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002651` | `SS/kmc` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002651` | `SS/ss-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002651` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002651` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002651` | `SSSC/serverconfig-ss` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002654` | `OEP/ob-promotion` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002654` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002654` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002654` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002850` | `DOS/dosub` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002885` | `DET/fts` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002885` | `TER/t2a` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/gws-admin-be-api` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/gws-admin-be-batch` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/gws-admin-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/gws-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/gws-gateway-be-api` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/gws-point-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/gws-promotion-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/gws-promotion-consumer-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/gws-user-be-api` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/oki-admin-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/oki-be` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `GWS/oki-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `HGV/skhgv-hgv-pub-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `IDMS/idms01` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002899` | `IDMS/sqlloader` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002913` | `EMP/ocb-emp-api-if` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002915` | `BRG/rankinggame` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002915` | `DFS/bridge` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002915` | `DFS/mosquitto` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002915` | `DFS/php` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002925` | `JOYPOT/joypot-admin-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002925` | `JOYPOT/joypot-backend` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002929` | `OCB-MINT/mint-fe` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002929` | `VUL/mint-api` | ❌ | ❌ | ❌ | ❌ | — |
| OCB | `C002930` | `OCBSUGAR/ocb-vp-api` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001152` | `ROL/clever-cdn` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001425` | `PIC/picaso-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001425` | `PIC/picaso-ipf` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001571` | `PIC/solutionbe` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001571` | `PIC/solutionbeweb` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001764` | `ENCP/batch` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001764` | `PIC/solution.ad.batch` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001764` | `PLAC/place_p1_batch_datafeed` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001764` | `PLAC/place_p1_batch_di` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001764` | `PLAC/place_p1_batch_di_legacy` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001764` | `PLAC/place_p1_batch_env_management` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001764` | `PLAC/place_p1_batch_external` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001764` | `PLAC/place_p1_batch_internal` | ❌ | ❌ | ❌ | ❌ | — |
| PICASO | `C001767` | `PIC/springpicasogateway` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C000954` | `IPX/proxy-gifticon-b2b` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C000954` | `IPX/proxy-gifticon-int` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C000954` | `IPX/proxy-gifticon-pub` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C000954` | `IPX/tcpforward-gifticon-b2b` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C000954` | `IPX/tcpforward-gifticon-int` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C000954` | `IPX/tcpforward-gifticon-pub` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C001016` | `IPX/proxy-syrup-b2b` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C001016` | `IPX/proxy-syrup-int` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C001016` | `IPX/proxy-syrup-pub` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C001016` | `IPX/tcpforward-syrup-int` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C001524` | `IPX/proxy-data-int` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C001524` | `IPX/proxy-data-pub` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C001524` | `IPX/tcpforward-data-int` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C001524` | `IPX/tcpforward-data-pub` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/proxy-ocb-b2b` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/proxy-ocb-int` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/proxy-ocb-pub` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/proxy-ocb2-b2b` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/proxy-ocb2-int` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/proxy-ocb2-pub` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/tcpforward-ocb-b2b` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/tcpforward-ocb-int` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/tcpforward-ocb-pub` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/tcpforward-ocb2-b2b` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/tcpforward-ocb2-int` | ❌ | ❌ | ❌ | ❌ | — |
| Proxy | `C002520` | `IPX/tcpforward-ocb2-pub` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001176` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001176` | `SSI/ora_simple_analyzer` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001176` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001176` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001176` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001176` | `SW/dbif` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001176` | `SW/dbif_batch` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001176` | `SW/new_open_api` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001176` | `VRBT/scavenger` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `PFMS/qcshell` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `SSI/memcached-util` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `SW/iop_api` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `SW/iop_batch` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `SW/iop_batch_admin` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `SW/iop_batch_nexg` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001177` | `SW/iop_search_batch` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001179` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001179` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001179` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001179` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001179` | `SW/push_admin` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001179` | `SW/push_ctl` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001179` | `SW/push_flux` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001179` | `SW/push_mass` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001179` | `SW/push_msg` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001179` | `SW/pushsellscript` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001181` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001181` | `SSI/dummy_so` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001181` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001181` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001181` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001181` | `SW/appif-ktor` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001181` | `SW/appif5` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001181` | `SW/external_libs` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001181` | `VRBT/scavenger` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001182` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001182` | `SSI/dummy_so` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001182` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001182` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001182` | `SSSC/serverconfig-ss` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001182` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001182` | `SW/crypt` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001182` | `SW/crypt_api` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001182` | `SW/mt` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001185` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001185` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001185` | `SW/coupon_admin` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001185` | `SW/coupon_batch` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001185` | `SW/coupon_if` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001186` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001186` | `SSI/dummy_so` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001186` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001186` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001186` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001186` | `SW/mplus_cii` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001186` | `SW/syrup_cii_be` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001186` | `SW/syrup_cii_fe` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001186` | `SW/syrup_cs` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001186` | `SW/syrup_homepage` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SS/frontend-ia` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SS/frontend-ma` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SS/frontend-solutions` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SS/kmc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SS/ss-be` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SSI/cdnvalid` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SSI/dummy_so` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SSI/ora_simple_analyzer` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SSSC/serverconfig-ss` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001198` | `SW/dbro` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001419` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001419` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001419` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001419` | `SW/dbro` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001419` | `SW/gw_batch` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001419` | `SW/gw_in` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001419` | `SW/gw_out` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001419` | `SW/gw_out_homeplus` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001419` | `SW/gw_out_lotte` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001419` | `SW/syrup_cloud_gw` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001599` | `SS/kmc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001599` | `SS/ss-be` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001599` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001599` | `SSI/dummy_so` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001599` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C001599` | `SSSC/serverconfig-ss` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SSI/dummy_so` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SSSC/serverconfig-commonif` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SSSC/serverconfig-rr` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SSSC/serverconfig-ss` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SSSC/serverconfig-webtemplate` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SW/common-if` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SW/img_rr` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002317` | `SW/next-commonfe` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `ATMOS/atmos-main` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `JVS_1/pds_jarvis_dashboard` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `O2SS/pfms` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PALAB/devx-backend` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PALAB/pitsm-backend` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PFMS/e2e` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PFMS/fido` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PFMS/pfms-admin` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PFMS/pfms-fin` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PFMS/pfms-gold` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PFMS/pfms-lua` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PFMS/pfms-md` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PFMS/pfms-oz` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PFMS/pfms-oz-gw` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `PFMS/qcshell` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `SSI/dummy_so` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `SSSC/serverconfig-pfms` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `SSSC/serverconfig-pfms-gold` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `SSSC/serverconfig-pfms-mydata` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `SSSC/serverconfig-pfmsfin` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `SSSC/serverconfig-pfmsoz` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002818` | `SSSC/serverconfig-ss` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `PFMS/pfms-loancompare-fe` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `PFMS/pfms-lua` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SSI/dummy_so` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SSSC/serverconfig-commonif` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SSSC/serverconfig-pfms` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SSSC/serverconfig-ss` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SW/common-front` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SW/common-if` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SW/dbro` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SW/next-commonfe` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SW/shop` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002866` | `SW/statistic-fe` | ❌ | ❌ | ❌ | ❌ | — |
| Syrup | `C002870` | `OZPAY/oz-pay-socket` | ❌ | ❌ | ❌ | ❌ | — |
| 광고플랫폼 | `C001330` | `ADREPORT/adreport-be` | ❌ | ❌ | ❌ | ❌ | — |
| 광고플랫폼 | `C001330` | `ADREPORT/adreport-fe` | ❌ | ❌ | ❌ | ❌ | — |
| 광고플랫폼 | `C001650` | `ADP/cnvsnsvc` | ❌ | ❌ | ❌ | ❌ | — |
| 광고플랫폼 | `C001650` | `ADP/cs-admin-web` | ❌ | ❌ | ❌ | ❌ | — |
| 광고플랫폼 | `C001650` | `ADP/cssvc` | ❌ | ❌ | ❌ | ❌ | — |
| 광고플랫폼 | `C001894` | `ADP/cs-admin-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000935` | `SW/external_libs` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000935` | `VRBT/scavenger` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000970` | `IDMS/idms01` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000970` | `NIDMS/ipms_batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000970` | `NIDMS/uidms-employee` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000970` | `NIDMS/uidms-partners` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `DEP/dep-back` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `DEV/ha-script` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `JVS/ms-notification` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `JVS_1/awsjarvis` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `JVS_1/jarvis-ts-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `JVS_1/jarvis_playbook` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `JVS_1/jhistory-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `JVS_1/jhistory-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `JVS_1/pds_jarvis_dashboard` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `OCBNFT/ocb-nft-script` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C000995` | `PALAB/devx-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SSSC/serverconfig-ss` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SW/mplus_api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SW/mplus_batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SW/mplus_cii` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SW/mplus_event` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SW/mplus_madm` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SW/mplus_rms` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SW/mplus_sadm` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SW/syrup_cii_be` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SW/syrup_cii_fe` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001187` | `SW/syrup_cs` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001194` | `PROXSL/bsms-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001194` | `PROXSL/bsms-admin-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001194` | `PROXSL/install-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001197` | `ENCP/batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001197` | `PIC/solution.ad.batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001197` | `PLAC/imc` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001197` | `PLAC/place_p1_batch_datafeed` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001197` | `PLAC/place_p1_batch_env_management` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001197` | `PLAC/place_p1_batch_external` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001197` | `PLAC/place_p1_batch_internal` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001219` | `VOC/voc-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001219` | `VOC/voc-admin-fe` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001219` | `VOC/voc-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001219` | `VOC/voc-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001355` | `MYDATA/cert-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001355` | `MYDATA/ms-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001355` | `MYDATA/ms-discovery` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001355` | `MYDATA/ms-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001385` | `T/tacademy_admin_new` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001385` | `T/tacademy_batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001385` | `T/tacademy_front_new` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001391` | `AIMT/aimt-converter` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001391` | `AIMT/kustomize` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `ADS-DA/ca_public_data` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `ADS-DA/dic-airflow` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `ADS-DA/pa-aprefine-ml` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `ADS-DA/pa-capa` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `ADS-DA/pa-intent` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `ADS-DA/pa-udf` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `ADS-DA/podo_class1` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `ADS-DA/query_bank` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `FCP/fcp-csweb` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `JVS_1/pds_jarvis_dashboard` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXS/cs-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXS/mkt-service-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXS/mkt-service-admin-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXS/pcona` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXS/px-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXS/px-dmpz` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXS/px-open-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXS/px-policy-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXSL/ble-gw` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXSL/bsms-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXSL/bsms-admin-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXSL/geofence_server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXSL/install-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001429` | `PROXSL/wifi_server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-bank` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-card` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-ginsu` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-insu` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-invest` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-irp` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-oauth` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-result` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-retroact` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-syrup-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/ms-telecom` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/provider-discovery` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/provider-gw` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/provider-ice` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/provider-inquiry-history` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/provider-ocb` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/provider-sbs` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001438` | `MYDATA/provider-script` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001516` | `VCMP/vcmp` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001537` | `OCBNFT/ocb-nft-script` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001537` | `RECODEV/cf-recopick-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001537` | `RECODEV/reco-engine-dic` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001561` | `PIC/event-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001561` | `PIC/eventgatewayweb` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001604` | `TMMGR/tmmgr` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001604` | `TMMGR/tmmgr_tong` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001604` | `TMMGR/tmmgr_web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001667` | `PIC/allcoupon.ssa` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001667` | `PIC/newcoupon` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001667` | `PIC/skp-coupon` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001667` | `PIC/syrupwalletapi` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001667` | `PIC/syrupwalletbatchsys` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/airflow-dag-cdp` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/airflow-dag-dmp` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/airflow-plugin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/cdp-machine-learning` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-api-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-bulk-ingest` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-column-search-java` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-config-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-dashboard` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-dashboard-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-dashboard-under-construction` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-data-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-data-worker` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-esti-scoring` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-interface-shell` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-notification` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-onestore-google-play-scraper` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-open-discovery` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-open-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-script` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-trait-classifier` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-trait-ml` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-trait-rule` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp-worker-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp_di_airflow` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp_ds_filter` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp_pcona` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/dmp_remote_runner` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/ml_flow_new` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/trait_rule_engine_v2` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/trait_rule_engine_v3` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `DMP/trait_stat` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001702` | `VAS/starchip_user` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001714` | `TSS_SERVER/tsmartsafe_admin_renewal` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001714` | `TSS_SERVER/tsmartsafe_batch_ivr` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001714` | `TSS_SERVER/tsmartsafe_batch_kait` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001714` | `TSS_SERVER/tsmartsafe_batch_tot` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001714` | `TSS_SERVER/tsmartsafe_front_renewal` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001714` | `TSS_SERVER/tss_bat_2017` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001714` | `TSS_SERVER/tss_bc_2020` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001714` | `VRBT/scavenger-agent` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001717` | `O2SS/solution` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001717` | `SSI/clo_file_decryptor` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001717` | `SSI/dbro_clo` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001717` | `SSI/dist_clo_file_decryptor` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001717` | `SSI/dummy_jar` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001717` | `SSSC/serverconfig-clo` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001717` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001717` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001717` | `SSSC/serverconfig-ss` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001717` | `SSSC/serverconfig-webtemplate` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001746` | `VRBT/scavenger` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `LKICK/lkick-event-batch-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `LKICK/lkick-event-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `LKICK/lkick-event-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `LKICK/lkick-reward-batch-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `LKICK/lkick-reward-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `LKICK/lkick-reward-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `SW/syrup_culture_b2b_ticket` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `SW/syrup_culture_frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `SW/syrup_culture_skmc_salecompany_benepia` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `SW/syrup_culture_skmc_salecompany_benepiam` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `SW/syrup_culture_skmc_salecompany_hanaskcard` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `SW/syrup_culture_skmc_salecompany_hanaskcardm` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `SW/syrup_culture_skmc_salecompany_masil` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `SW/syrup_culture_skmc_salecompany_skt` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001748` | `SW/syrup_culture_skmc_salecompany_sktm` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001768` | `OBIZ/obiz-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001768` | `OBIZ/obiz-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001768` | `OBIZ/obiz-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001768` | `OBIZ/obiz-batch2` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001768` | `OBIZ/obiz-mt-mgr` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001768` | `OBIZ/obiz-rlc-info` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001768` | `OBIZ/obiz-survey-agent` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001768` | `OBIZ/obiz-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001780` | `PST/pstore` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001780` | `PST/pstoreadmin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-api-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-column-search-java` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-dashboard` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-dashboard-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-dashboard-under-construction` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-data-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-esti-scoring` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-id-sync` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-intelligence-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-interface-shell` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-oauth-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-script` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-terms` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-trait-classifier` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp-user-pcona-segment-upload-redis` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp_pcona` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp_remote_runner` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/dmp_upload_redis_v2` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/segment-engine` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `DMP/trait_stat` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001823` | `OTUBE/otube-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001855` | `KHUB_PORTAL/khub-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001855` | `KHUB_PORTAL/khub-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001855` | `KHUB_PORTAL/khub-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C001963` | `BOTSOL/csmail-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/cdp-machine-learning` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-api-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-column-search-java` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-dashboard` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-dashboard-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-dashboard-under-construction` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-data-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-esti-scoring` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-intelligence-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-interface-shell` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-oauth-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-script` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-trait-classifier` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp-trait-rule` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/dmp_remote_runner` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/segment-engine` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002038` | `DMP/trait_stat` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002043` | `PALAB/private-chatbot-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002043` | `PALAB/rag-chatbot-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002043` | `PALAB/rag-chatbot-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002043` | `PALAB/rag-chatbot-langchain-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002309` | `LMS/lms-admin-fe` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002309` | `TSAFTYDEV/learningworld` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-bank` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-capital` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-card` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-invest` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-irp` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-oauth` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-ocb-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-result` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-support` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002327` | `MYDATA/ms-syrup-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002354` | `PROXS/cs-service` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002400` | `SKPIE/opsdb_api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002400` | `SKPIE/opsdb_batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002400` | `SKPIE/opsdb_webui` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002401` | `SKPIE/opsdb_api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002401` | `SKPIE/opsdb_webui` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002401` | `SKPIE/pams-ui` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002401` | `SKPIE/pams_batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/il-spring-monitoring` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-admin-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-channel` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-controller` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-eureka` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-media` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-media-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-play` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-registry` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-snap-proxy` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-tablet-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002452` | `AIDEV2/smartdt-tv-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002455` | `RECODEV/reco-engine-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002456` | `RECODEV/recopick-cf-batch-manager` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002462` | `JVS_1/pds_jarvis_dashboard` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002462` | `PALAB/logx-alert` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002462` | `PALAB/logx-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002462` | `PALAB/logx-notification` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002462` | `PALAB/logx-nxmnoti` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002462` | `PALAB/logx-relay-svr` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002462` | `PALAB/logx-scheduler-framework` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002462` | `PALAB/realx-frontend-renewal` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002462` | `PALAB/slack-new-bot` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002462` | `PALAB/visuallayer_grafana_v706` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002464` | `PALAB/pitsm-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002521` | `SKICK/skick-event-batch-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002521` | `SKICK/skick-event-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002521` | `SKICK/skick-event-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002521` | `SKICK/skick-reward-batch-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002521` | `SKICK/skick-reward-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002521` | `SKICK/skick-reward-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002527` | `MIP/phonesafe-project` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002527` | `MIP/phonesafe_real-2-mail` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002547` | `APPMON/mon_server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002547` | `QAC/qax` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002565` | `DM/tiisweb_openapi` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002565` | `DM/tiisweb_tiisapp` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002602` | `PROXS/pcona` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002664` | `FCP/fcp-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002664` | `FCP/fcp-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002766` | `PALAB/cp-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002766` | `PALAB/devx-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002766` | `PALAB/devx-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002766` | `PALAB/pitsm-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002766` | `PALAB/pitsm-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002766` | `PALAB/sp-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002766` | `PALAB/sp-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002766` | `SSSC/serverconfig-common` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002766` | `SSSC/serverconfig-fc` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BAG/biz-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BAG/biz-api-gw` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BAG/biz-api-test` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BAG/biz-mobile-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BAG/biz-rcs-mng` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BAG/biz-vmg-mng` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BAG/biz-webhook` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BIZ/mmate-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BIZ/mmate-agent` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BIZ/mmate-async` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BIZ/mmate-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BIZ/mmate-batch2` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BIZ/mmate-rlc-info` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `BIZ/mmate-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `IMP/imp-msg-test` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `IMP/mmate-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `IMP/mmate-mms-skt` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `IMP/mmate-mt-mgr` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `IMP/mmate-rcs-skt` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `IMP/mmate-sms-skt` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `IMP/mmate-survey-agent` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `OTP/mmate-otp-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002772` | `OTP/mmate-otp-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002779` | `VAS/starchip2-user-fe` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002788` | `AIPLTM/ai-platform-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002788` | `AIPLTM/ai-platform-fe` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002800` | `TSAFE/portalwas_voc` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002800` | `TSAFE/socketwas_duplex2` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002800` | `TSAFE/socketwas_push2` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002800` | `TSAFTYDEV/portalwas_tworld_premium` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002800` | `VRBT/scavenger-agent` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002803` | `TCALL/tcall-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002803` | `TCALL/tcall-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002803` | `TCALL/tcall-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002803` | `TCALL/tcall-feapi` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002803` | `TCALL/tcall-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002804` | `TCALL/vas-open-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002804` | `VASGW/vasgw-api` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002804` | `VASGW/vasgw_admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002811` | `TUMS/junewas` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002811` | `TUMS/tums_grigo` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002811` | `TUMS/tums_web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002825` | `AIDEV2/air-discovery` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002825` | `AIDEV2/air-notification` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002825` | `AIDEV2/air-play-happy-comm-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002825` | `AIDEV2/air-play-happy-comm-batch` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002825` | `AIDEV2/air-play-happy-comm-push-scheduler` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002825` | `AIDEV2/air-play-silver-friend-admin-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002825` | `AIDEV2/air-port` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002825` | `AIDEV2/airframework-project-happy-community` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002825` | `AIDEV2/happy-community-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/k8s` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/pinpoint` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/pinpoint-agent` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/pinpoint-docker` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/pinpoint-receiver` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/scavenger-agent` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/vbiz-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/vrbt-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/vrbt-fe-monorepo` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/vrbt-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/vrbt-frontend-next` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/vrbt-nginx` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/vrbt-oem-convert` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/vrbt-push` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002848` | `VRBT/vrbt-tworld` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002865` | `SW/mplus_event` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002887` | `TUMS/bell_admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002887` | `TUMS/bell_service` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002907` | `SKPOF/log-monitor` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002907` | `SKPOF/skp_admin_server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002907` | `SKPOF/skp_logger` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002907` | `SKPOF/skp_updater` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002908` | `TALKS/oggletalk-admin-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002908` | `TALKS/oggletalk-backend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002908` | `TALKS/talkplanet-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002908` | `TALKS/talks-deploy` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002910` | `SLO/optimize-lottie` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002910` | `SLO/webpgenerator` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002911` | `PMHP/planet-m-m-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002911` | `PMHP/planet-m-pc-web` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002911` | `SSSC/serverconfig-syrup` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002912` | `BAG/biz-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002912` | `BAG/biz-api-gw` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002912` | `BAG/biz-mobile-admin` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002912` | `BAG/biz-rcs-mng` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002912` | `BAG/biz-vmg-mng` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002912` | `BAG/biz-webhook` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002923` | `ADREPORT/adecs-be` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002923` | `ADREPORT/adecs-fe` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002923` | `ADREPORT/ocbhotplace-be` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002923` | `ADREPORT/ocbhotplace-fe` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002924` | `QUERKA/querka-agent` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002924` | `QUERKA/querka-fe` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002926` | `OUT/outlink-api-gw` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002926` | `OUT/outlink-rcs-mng` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002926` | `OUT/outlink-vmg-mng` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002926` | `OUT/outlink-webhook` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002927` | `ELEVENKICK/11kick-event-batch-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002927` | `ELEVENKICK/11kick-event-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002927` | `ELEVENKICK/11kick-event-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002927` | `ELEVENKICK/11kick-reward-batch-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002927` | `ELEVENKICK/11kick-reward-front` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C002927` | `ELEVENKICK/11kick-reward-server` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C999999` | `DMP/dmp-api-gateway` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C999999` | `DMP/dmp-script` | ❌ | ❌ | ❌ | ❌ | — |
| 미분류 | `C999999` | `PALAB/sp-frontend` | ❌ | ❌ | ❌ | ❌ | — |
| 보안 | `C001132` | `PMON/pmon_alarm_proc` | ❌ | ❌ | ❌ | ❌ | — |
| 보안 | `C001132` | `PMON/pmon_service_proc` | ❌ | ❌ | ❌ | ❌ | — |
| 보안 | `C001132` | `PMON/pmon_system_proc` | ❌ | ❌ | ❌ | ❌ | — |
| 보안 | `C001132` | `PNS/notification-mon` | ❌ | ❌ | ❌ | ❌ | — |
| 인프라운영 | `C001403` | `MEC/me_conf` | ❌ | ❌ | ❌ | ❌ | — |
| 인프라운영 | `C001403` | `MID/root` | ❌ | ❌ | ❌ | ❌ | — |
| 인프라운영 | `C001545` | `CLOUD/pmm_helm_charts` | ❌ | ❌ | ❌ | ❌ | — |
| 인프라운영 | `C001545` | `MEC/me_conf` | ❌ | ❌ | ❌ | ❌ | — |
| 인프라운영 | `C001545` | `MEC/midc_test_certi` | ❌ | ❌ | ❌ | ❌ | — |
:::

## 3. 다중 시스템코드 매핑 레포 (확인 필요, 152건)

> 동일 레포가 CMDB 상 여러 시스템코드에 연결되어 있음 — 실제 소속 시스템코드를 담당자 확인 후 정리 필요.

:::expand 다중 시스템코드 매핑 레포 — 실제 매핑 확인 필요 (152건, 클릭하여 펼치기)

| 레포 | 매핑된 시스템코드 (N개) | 비고 |
|---|---|---|
| `airflow_bi_custpfdb` | `C000952`(DI-Cluster), `C001778`(BI서비스-DIIF) (2개) | 확인 필요 |
| `airflow_bi_ocb` | `C000952`(DI-Cluster), `C001778`(BI서비스-DIIF) (2개) | 확인 필요 |
| `airflow_bi_proximity` | `C000952`(DI-Cluster), `C001778`(BI서비스-DIIF) (2개) | 확인 필요 |
| `airflow_bi_syrupstore` | `C000952`(DI-Cluster), `C001778`(BI서비스-DIIF) (2개) | 확인 필요 |
| `airflow_bi_syrupwallet` | `C000952`(DI-Cluster), `C001778`(BI서비스-DIIF) (2개) | 확인 필요 |
| `batch` | `C001197`(IMC), `C001764`(PICASO-IMC) (2개) | 확인 필요 |
| `batch-script` | `C001197`(IMC), `C001764`(PICASO-IMC) (2개) | 확인 필요 |
| `biz-admin` | `C002772`(BizChat), `C002912`(BCHAT-API) (2개) | 확인 필요 |
| `biz-api-gw` | `C002772`(BizChat), `C002912`(BCHAT-API) (2개) | 확인 필요 |
| `biz-mobile-admin` | `C002772`(BizChat), `C002912`(BCHAT-API) (2개) | 확인 필요 |
| `biz-rcs-mng` | `C002772`(BizChat), `C002912`(BCHAT-API) (2개) | 확인 필요 |
| `biz-vmg-mng` | `C002772`(BizChat), `C002912`(BCHAT-API) (2개) | 확인 필요 |
| `biz-webhook` | `C002772`(BizChat), `C002912`(BCHAT-API) (2개) | 확인 필요 |
| `blacksmith` | `C000962`(DI-s3upload), `C001148`(DI-NG) (2개) | 확인 필요 |
| `bsms-admin` | `C001194`(Proximity), `C001429`(Proximity) (2개) | 확인 필요 |
| `bsms-admin-front` | `C001194`(Proximity), `C001429`(Proximity) (2개) | 확인 필요 |
| `cashbagmall` | `C001743`(OCB-캐쉬백몰(적립)), `C002858`(OCB-캐쉬백몰(front)) (2개) | 확인 필요 |
| `cdp-machine-learning` | `C001702`(DMP), `C002038`(DMP-실명) (2개) | 확인 필요 |
| `chat-dic-front` | `C000952`(DI-Cluster), `C002897`(DI-AI) (2개) | 확인 필요 |
| `cms_resource` | `C001053`(OCB-mobile), `C001055`(OCB-CMSadmin), `C001527`(OCB이벤트-PoC), `C002654`(OCB이벤트-Promotion) (4개) | 확인 필요 |
| `common-if` | `C002317`(SyrupWallet-ImageRR), `C002866`(SyrupWallet-CIF) (2개) | 확인 필요 |
| `cs-admin-web` | `C001650`(광고플랫폼-PlanetAD), `C001894`(광고플랫폼-PlanetAD) (2개) | 확인 필요 |
| `dataflow` | `C001148`(DI-NG), `C001881`(OCB-NFT) (2개) | 확인 필요 |
| `dbro` | `C001198`(SyrupStore-IS), `C001419`(SyrupWallet-Gateway), `C002866`(SyrupWallet-CIF) (3개) | 확인 필요 |
| `dep-back` | `C000995`(JARVIS), `C001706`(BI서비스-ANALOG) (2개) | 확인 필요 |
| `devx-backend` | `C000995`(JARVIS), `C002766`(개발환경포털), `C002818`(SyrupWallet-PFMS) (3개) | 확인 필요 |
| `di-airflow-dags` | `C000952`(DI-Cluster), `C002838`(DI-Boat(k8s)) (2개) | 확인 필요 |
| `di-airflow-packages` | `C000952`(DI-Cluster), `C001148`(DI-NG), `C002838`(DI-Boat(k8s)) (3개) | 확인 필요 |
| `di-erlang` | `C001148`(DI-NG), `C001601`(DI-trino) (2개) | 확인 필요 |
| `di-findclass` | `C001148`(DI-NG), `C002467`(DI-Elastic) (2개) | 확인 필요 |
| `di-jdk` | `C000952`(DI-Cluster), `C001148`(DI-NG), `C002384`(DI-proxy), `C002467`(DI-Elastic), `C002476`(DI-QueryCache) (5개) | 확인 필요 |
| `di-rdbms-metrics` | `C001601`(DI-trino), `C002467`(DI-Elastic) (2개) | 확인 필요 |
| `di-shell-utils` | `C001148`(DI-NG), `C001601`(DI-trino), `C002384`(DI-proxy) (3개) | 확인 필요 |
| `di-utils` | `C001148`(DI-NG), `C001601`(DI-trino), `C002467`(DI-Elastic), `C002476`(DI-QueryCache) (4개) | 확인 필요 |
| `dmp-api-gateway` | `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명), `C999999`(개발환경포털) (4개) | 확인 필요 |
| `dmp-column-search-java` | `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명) (3개) | 확인 필요 |
| `dmp-dashboard` | `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명) (3개) | 확인 필요 |
| `dmp-dashboard-api` | `C001823`(DMP-비실명), `C002038`(DMP-실명) (2개) | 확인 필요 |
| `dmp-dashboard-under-construction` | `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명) (3개) | 확인 필요 |
| `dmp-data-api` | `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명) (3개) | 확인 필요 |
| `dmp-esti-scoring` | `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명) (3개) | 확인 필요 |
| `dmp-intelligence-api` | `C001823`(DMP-비실명), `C002038`(DMP-실명) (2개) | 확인 필요 |
| `dmp-interface-shell` | `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명) (3개) | 확인 필요 |
| `dmp-oauth-api` | `C001823`(DMP-비실명), `C002038`(DMP-실명) (2개) | 확인 필요 |
| `dmp-open-gateway` | `C001072`(OCB-WebView), `C001702`(DMP) (2개) | 확인 필요 |
| `dmp-script` | `C001072`(OCB-WebView), `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명), `C999999`(개발환경포털) (5개) | 확인 필요 |
| `dmp-trait-classifier` | `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명) (3개) | 확인 필요 |
| `dmp-trait-rule` | `C001702`(DMP), `C002038`(DMP-실명) (2개) | 확인 필요 |
| `dmp_di_airflow` | `C000952`(DI-Cluster), `C001702`(DMP) (2개) | 확인 필요 |
| `dmp_pcona` | `C001702`(DMP), `C001823`(DMP-비실명) (2개) | 확인 필요 |
| `dmp_remote_runner` | `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명) (3개) | 확인 필요 |
| `dummy_jar` | `C001068`(OCBpass), `C001070`(OCB-Sugar), `C001176`(SyrupWallet-DBIF), `C001177`(SyrupWallet-IOP), `C001179`(SyrupWallet-Push), `C001181`(SyrupWallet-APPIF), `C001182`(SyrupWallet-MT), `C001185`(SyrupWallet-Coupon), `C001186`(SyrupWallet홈페이지), `C001187`(마케팅플러스), `C001198`(SyrupStore-IS), `C001419`(SyrupWallet-Gateway), `C001599`(SyrupStore-Auth), `C001717`(O2O솔루션-CLO), `C002317`(SyrupWallet-ImageRR), `C002651`(OCB-통장암호화), `C002818`(SyrupWallet-PFMS), `C002866`(SyrupWallet-CIF) (18개) | 확인 필요 |
| `dummy_so` | `C001181`(SyrupWallet-APPIF), `C001182`(SyrupWallet-MT), `C001186`(SyrupWallet홈페이지), `C001198`(SyrupStore-IS), `C001599`(SyrupStore-Auth), `C002317`(SyrupWallet-ImageRR), `C002818`(SyrupWallet-PFMS), `C002866`(SyrupWallet-CIF) (8개) | 확인 필요 |
| `external_libs` | `C000935`(데드코드분석-전금법), `C001181`(SyrupWallet-APPIF) (2개) | 확인 필요 |
| `galleon` | `C000950`(DI-Galleon), `C001148`(DI-NG) (2개) | 확인 필요 |
| `gw_out` | `C001068`(OCBpass), `C001070`(OCB-Sugar), `C001419`(SyrupWallet-Gateway) (3개) | 확인 필요 |
| `gw_out_homeplus` | `C001068`(OCBpass), `C001419`(SyrupWallet-Gateway) (2개) | 확인 필요 |
| `gws-admin-be-api` | `C001072`(OCB-WebView), `C002651`(OCB-통장암호화), `C002899`(OCB-쇼핑적립) (3개) | 확인 필요 |
| `gws-admin-be-batch` | `C001072`(OCB-WebView), `C002899`(OCB-쇼핑적립) (2개) | 확인 필요 |
| `gws-admin-fe` | `C001072`(OCB-WebView), `C002899`(OCB-쇼핑적립) (2개) | 확인 필요 |
| `gws-point-be` | `C001070`(OCB-Sugar), `C001072`(OCB-WebView), `C002899`(OCB-쇼핑적립) (3개) | 확인 필요 |
| `gws-promotion-be` | `C002651`(OCB-통장암호화), `C002899`(OCB-쇼핑적립) (2개) | 확인 필요 |
| `gws-promotion-consumer-be` | `C002651`(OCB-통장암호화), `C002899`(OCB-쇼핑적립) (2개) | 확인 필요 |
| `helm-charts` | `C000952`(DI-Cluster), `C001881`(OCB-NFT) (2개) | 확인 필요 |
| `hive-admin` | `C000956`(DI-kafka), `C001148`(DI-NG), `C002701`(DI-hive) (3개) | 확인 필요 |
| `hive-airlock-manager` | `C000956`(DI-kafka), `C002701`(DI-hive) (2개) | 확인 필요 |
| `hive-audit-hook` | `C000956`(DI-kafka), `C002701`(DI-hive) (2개) | 확인 필요 |
| `hive-configs` | `C000956`(DI-kafka), `C001148`(DI-NG), `C002701`(DI-hive) (3개) | 확인 필요 |
| `idms01` | `C000970`(IPMS), `C002899`(OCB-쇼핑적립) (2개) | 확인 필요 |
| `impala-kudu` | `C001601`(DI-trino), `C002467`(DI-Elastic) (2개) | 확인 필요 |
| `install-api` | `C001194`(Proximity), `C001429`(Proximity) (2개) | 확인 필요 |
| `install-cert` | `C001148`(DI-NG), `C002384`(DI-proxy) (2개) | 확인 필요 |
| `jdbc-tester` | `C001000`(DI-LogSentinel), `C001148`(DI-NG), `C002384`(DI-proxy), `C002467`(DI-Elastic), `C002476`(DI-QueryCache) (5개) | 확인 필요 |
| `kmc` | `C001198`(SyrupStore-IS), `C001599`(SyrupStore-Auth), `C002651`(OCB-통장암호화) (3개) | 확인 필요 |
| `lake` | `C000952`(DI-Cluster), `C001070`(OCB-Sugar), `C001149`(DI-Rake) (3개) | 확인 필요 |
| `me_conf` | `C001403`(MGMT-ME), `C001545`(MGMT-ME), `C002289`(OCB-PAYUI(간편사용)) (3개) | 확인 필요 |
| `mongodb-conf` | `C001601`(DI-trino), `C002467`(DI-Elastic) (2개) | 확인 필요 |
| `mplus_cii` | `C001186`(SyrupWallet홈페이지), `C001187`(마케팅플러스) (2개) | 확인 필요 |
| `mplus_event` | `C001187`(마케팅플러스), `C002865`(마케팅플러스-Event) (2개) | 확인 필요 |
| `ms-bank` | `C001438`(마이데이터-정보제공(MyDATA)), `C002327`(기프티콘) (2개) | 확인 필요 |
| `ms-batch` | `C001355`(기프티콘-엔쿠폰), `C002327`(기프티콘) (2개) | 확인 필요 |
| `ms-card` | `C001438`(마이데이터-정보제공(MyDATA)), `C002327`(기프티콘) (2개) | 확인 필요 |
| `ms-gateway` | `C001355`(기프티콘-엔쿠폰), `C002327`(기프티콘) (2개) | 확인 필요 |
| `ms-invest` | `C001438`(마이데이터-정보제공(MyDATA)), `C002327`(기프티콘) (2개) | 확인 필요 |
| `ms-irp` | `C001438`(마이데이터-정보제공(MyDATA)), `C002327`(기프티콘) (2개) | 확인 필요 |
| `ms-oauth` | `C001438`(마이데이터-정보제공(MyDATA)), `C002327`(기프티콘) (2개) | 확인 필요 |
| `ms-result` | `C001438`(마이데이터-정보제공(MyDATA)), `C002327`(기프티콘) (2개) | 확인 필요 |
| `ms-syrup-api` | `C001438`(마이데이터-정보제공(MyDATA)), `C002327`(기프티콘) (2개) | 확인 필요 |
| `next-commonfe` | `C002317`(SyrupWallet-ImageRR), `C002866`(SyrupWallet-CIF) (2개) | 확인 필요 |
| `nginx-configs` | `C000952`(DI-Cluster), `C001148`(DI-NG) (2개) | 확인 필요 |
| `ocb-api-with-python` | `C001070`(OCB-Sugar), `C002454`(OCB-AI쇼핑비서) (2개) | 확인 필요 |
| `ocb-appevt` | `C001070`(OCB-Sugar), `C001437`(OCB이벤트-AppEvt) (2개) | 확인 필요 |
| `ocb-nft-admin-front` | `C000952`(DI-Cluster), `C001881`(OCB-NFT) (2개) | 확인 필요 |
| `ocb-nft-backend` | `C000952`(DI-Cluster), `C000956`(DI-kafka), `C000995`(JARVIS), `C001068`(OCBpass), `C001070`(OCB-Sugar), `C001881`(OCB-NFT), `C002838`(DI-Boat(k8s)) (7개) | 확인 필요 |
| `ocb-nft-batch` | `C000952`(DI-Cluster), `C001068`(OCBpass) (2개) | 확인 필요 |
| `ocb-nft-fingerlabs` | `C000952`(DI-Cluster), `C001070`(OCB-Sugar), `C001881`(OCB-NFT) (3개) | 확인 필요 |
| `ocb-nft-homepage` | `C001068`(OCBpass), `C001881`(OCB-NFT) (2개) | 확인 필요 |
| `ocb-nft-script` | `C000952`(DI-Cluster), `C000956`(DI-kafka), `C000995`(JARVIS), `C001068`(OCBpass), `C001070`(OCB-Sugar), `C001537`(Recopick-DIIF), `C001881`(OCB-NFT), `C002838`(DI-Boat(k8s)) (8개) | 확인 필요 |
| `ocb-webview-frontend` | `C001072`(OCB-WebView), `C002925`(OCB-복지포인트) (2개) | 확인 필요 |
| `ocb-webview-reward-api` | `C001070`(OCB-Sugar), `C001881`(OCB-NFT) (2개) | 확인 필요 |
| `ocb_module` | `C001053`(OCB-mobile), `C001054`(OCB-com), `C001055`(OCB-CMSadmin) (3개) | 확인 필요 |
| `ocbpayui-frontend-web` | `C002289`(OCB-PAYUI(간편사용)), `C002388`(OCB-LoginUI(간편로그인)) (2개) | 확인 필요 |
| `oggreapi` | `C000952`(DI-Cluster), `C001148`(DI-NG) (2개) | 확인 필요 |
| `oki-admin-fe` | `C001072`(OCB-WebView), `C002899`(OCB-쇼핑적립) (2개) | 확인 필요 |
| `oki-be` | `C001070`(OCB-Sugar), `C001072`(OCB-WebView), `C002651`(OCB-통장암호화), `C002899`(OCB-쇼핑적립) (4개) | 확인 필요 |
| `opsdb_api` | `C002400`(INFRA-ITSM), `C002401`(INFRA-opsdb) (2개) | 확인 필요 |
| `opsdb_webui` | `C002400`(INFRA-ITSM), `C002401`(INFRA-opsdb) (2개) | 확인 필요 |
| `ora_simple_analyzer` | `C001176`(SyrupWallet-DBIF), `C001198`(SyrupStore-IS) (2개) | 확인 필요 |
| `pcona` | `C001429`(Proximity), `C002602`(PCONA) (2개) | 확인 필요 |
| `pds_jarvis_dashboard` | `C000995`(JARVIS), `C001429`(Proximity), `C001706`(BI서비스-ANALOG), `C002462`(LOGX), `C002818`(SyrupWallet-PFMS) (5개) | 확인 필요 |
| `pfms-lua` | `C002818`(SyrupWallet-PFMS), `C002866`(SyrupWallet-CIF) (2개) | 확인 필요 |
| `pitsm-backend` | `C002464`(CI빌드관리), `C002766`(개발환경포털), `C002818`(SyrupWallet-PFMS) (3개) | 확인 필요 |
| `place_p1_batch_datafeed` | `C001197`(IMC), `C001764`(PICASO-IMC) (2개) | 확인 필요 |
| `place_p1_batch_env_management` | `C001197`(IMC), `C001764`(PICASO-IMC) (2개) | 확인 필요 |
| `place_p1_batch_external` | `C001197`(IMC), `C001764`(PICASO-IMC) (2개) | 확인 필요 |
| `place_p1_batch_internal` | `C001197`(IMC), `C001764`(PICASO-IMC) (2개) | 확인 필요 |
| `presto-configs` | `C001601`(DI-trino), `C002467`(DI-Elastic) (2개) | 확인 필요 |
| `proxy-configs` | `C002384`(DI-proxy), `C002476`(DI-QueryCache) (2개) | 확인 필요 |
| `qcshell` | `C001177`(SyrupWallet-IOP), `C002818`(SyrupWallet-PFMS) (2개) | 확인 필요 |
| `querycache` | `C000956`(DI-kafka), `C001148`(DI-NG), `C002384`(DI-proxy), `C002476`(DI-QueryCache), `C002701`(DI-hive), `C002838`(DI-Boat(k8s)) (6개) | 확인 필요 |
| `querycache-conf` | `C002384`(DI-proxy), `C002476`(DI-QueryCache) (2개) | 확인 필요 |
| `querycache-conf.fdic` | `C002384`(DI-proxy), `C002476`(DI-QueryCache) (2개) | 확인 필요 |
| `querycache2` | `C000952`(DI-Cluster), `C000956`(DI-kafka), `C001148`(DI-NG), `C001601`(DI-trino), `C002384`(DI-proxy), `C002476`(DI-QueryCache), `C002701`(DI-hive), `C002838`(DI-Boat(k8s)) (8개) | 확인 필요 |
| `rake` | `C000952`(DI-Cluster), `C001070`(OCB-Sugar), `C001149`(DI-Rake) (3개) | 확인 필요 |
| `rangerbox-cron` | `C000952`(DI-Cluster), `C001148`(DI-NG) (2개) | 확인 필요 |
| `rangerbox-was` | `C000952`(DI-Cluster), `C001148`(DI-NG) (2개) | 확인 필요 |
| `redis-configs` | `C001601`(DI-trino), `C002476`(DI-QueryCache) (2개) | 확인 필요 |
| `router` | `C000952`(DI-Cluster), `C000956`(DI-kafka), `C001148`(DI-NG) (3개) | 확인 필요 |
| `router-connect` | `C000956`(DI-kafka), `C001148`(DI-NG) (2개) | 확인 필요 |
| `scavenger` | `C000935`(데드코드분석-전금법), `C001176`(SyrupWallet-DBIF), `C001181`(SyrupWallet-APPIF), `C001746`(데드코드분석) (4개) | 확인 필요 |
| `scavenger-agent` | `C001714`(T스마트세이프), `C002800`(T안심콜), `C002848`(V컬러링) (3개) | 확인 필요 |
| `segment-engine` | `C000952`(DI-Cluster), `C001823`(DMP-비실명), `C002038`(DMP-실명) (3개) | 확인 필요 |
| `serverconfig-common` | `C001068`(OCBpass), `C001176`(SyrupWallet-DBIF), `C001177`(SyrupWallet-IOP), `C001179`(SyrupWallet-Push), `C001181`(SyrupWallet-APPIF), `C001182`(SyrupWallet-MT), `C001185`(SyrupWallet-Coupon), `C001186`(SyrupWallet홈페이지), `C001198`(SyrupStore-IS), `C001419`(SyrupWallet-Gateway), `C001599`(SyrupStore-Auth), `C001717`(O2O솔루션-CLO), `C002317`(SyrupWallet-ImageRR), `C002651`(OCB-통장암호화), `C002654`(OCB이벤트-Promotion), `C002766`(개발환경포털), `C002818`(SyrupWallet-PFMS), `C002866`(SyrupWallet-CIF) (18개) | 확인 필요 |
| `serverconfig-commonif` | `C002317`(SyrupWallet-ImageRR), `C002866`(SyrupWallet-CIF) (2개) | 확인 필요 |
| `serverconfig-fc` | `C001176`(SyrupWallet-DBIF), `C001177`(SyrupWallet-IOP), `C001179`(SyrupWallet-Push), `C001181`(SyrupWallet-APPIF), `C001182`(SyrupWallet-MT), `C001186`(SyrupWallet홈페이지), `C001187`(마케팅플러스), `C001198`(SyrupStore-IS), `C001717`(O2O솔루션-CLO), `C002317`(SyrupWallet-ImageRR), `C002654`(OCB이벤트-Promotion), `C002766`(개발환경포털), `C002818`(SyrupWallet-PFMS), `C002866`(SyrupWallet-CIF) (14개) | 확인 필요 |
| `serverconfig-pfms` | `C002818`(SyrupWallet-PFMS), `C002866`(SyrupWallet-CIF) (2개) | 확인 필요 |
| `serverconfig-ss` | `C001182`(SyrupWallet-MT), `C001187`(마케팅플러스), `C001198`(SyrupStore-IS), `C001599`(SyrupStore-Auth), `C001717`(O2O솔루션-CLO), `C002317`(SyrupWallet-ImageRR), `C002651`(OCB-통장암호화), `C002818`(SyrupWallet-PFMS), `C002866`(SyrupWallet-CIF) (9개) | 확인 필요 |
| `serverconfig-syrup` | `C001068`(OCBpass), `C001070`(OCB-Sugar), `C001176`(SyrupWallet-DBIF), `C001177`(SyrupWallet-IOP), `C001179`(SyrupWallet-Push), `C001181`(SyrupWallet-APPIF), `C001182`(SyrupWallet-MT), `C001186`(SyrupWallet홈페이지), `C001187`(마케팅플러스), `C001419`(SyrupWallet-Gateway), `C001509`(OCB-Locker), `C002317`(SyrupWallet-ImageRR), `C002654`(OCB이벤트-Promotion), `C002866`(SyrupWallet-CIF), `C002911`(PlanetM) (15개) | 확인 필요 |
| `serverconfig-webtemplate` | `C001717`(O2O솔루션-CLO), `C002317`(SyrupWallet-ImageRR) (2개) | 확인 필요 |
| `skhgv-hgv-pub-fe` | `C001759`(OCB-쇼핑적립), `C002899`(OCB-쇼핑적립) (2개) | 확인 필요 |
| `solution.ad.batch` | `C001197`(IMC), `C001764`(PICASO-IMC) (2개) | 확인 필요 |
| `sp-frontend` | `C002766`(개발환경포털), `C999999`(개발환경포털) (2개) | 확인 필요 |
| `ss-be` | `C001198`(SyrupStore-IS), `C001599`(SyrupStore-Auth), `C002651`(OCB-통장암호화) (3개) | 확인 필요 |
| `starchip2-user-fe` | `C001068`(OCBpass), `C002779`(VAS신규-스타칩2 담당자) (2개) | 확인 필요 |
| `starchip_admin` | `C001068`(OCBpass), `C001070`(OCB-Sugar) (2개) | 확인 필요 |
| `syrup_cii_be` | `C001186`(SyrupWallet홈페이지), `C001187`(마케팅플러스) (2개) | 확인 필요 |
| `syrup_cii_fe` | `C001186`(SyrupWallet홈페이지), `C001187`(마케팅플러스) (2개) | 확인 필요 |
| `syrup_cs` | `C001186`(SyrupWallet홈페이지), `C001187`(마케팅플러스) (2개) | 확인 필요 |
| `t2a` | `C001778`(BI서비스-DIIF), `C002885`(OCB-TM(보험)) (2개) | 확인 필요 |
| `trait_stat` | `C001702`(DMP), `C001823`(DMP-비실명), `C002038`(DMP-실명) (3개) | 확인 필요 |
| `trino-configs` | `C001601`(DI-trino), `C002467`(DI-Elastic) (2개) | 확인 필요 |
| `trino-monitor` | `C001601`(DI-trino), `C002467`(DI-Elastic) (2개) | 확인 필요 |
:::
