#!/usr/bin/env python3
"""
scan_injection_rules.py — Injection 진단 룰 레지스트리

Rule / Engine 분리 아키텍처:
  - 이 파일: 언어·프레임워크 특화 지식 (Source / Sink / Safe Binding 규칙)
  - scan_injection_enhanced.py: 범용 오케스트레이터 (RULE_REGISTRY 순회)

새 프레임워크 추가 방법:
  1. FrameworkRule 인스턴스 생성
  2. register_rule() 호출
  → 엔진 코드는 수정 불필요

FN 방어 원칙:
  - safe_binding_markers는 취약 후보를 「필터링」하는 데 절대 사용하지 않는다.
    안전 패턴 존재 여부는 결과 evidence에 주석으로만 기록하며,
    취약 후보의 존재 여부 판정 자체는 변경하지 않는다.
  - catch_all=True 프레임워크: DB 계층 클래스 내부에서 SQL 키워드 + 동적 결합이
    감지되면 실행 함수명과 무관하게 Sink 후보로 포착한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# 1. FrameworkRule 데이터 구조
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FrameworkRule:
    """단일 프레임워크/언어에 대한 인젝션 탐지 규칙 집합.

    Attributes
    ----------
    framework_id   : 고유 식별자 (예: "spring_jpa", "mybatis", "nodejs")
    lang_globs     : 적용 파일 확장자 패턴 (예: ["*.kt", "*.java"])
    db_layer_markers : DB 계층 클래스 식별 정규식 목록.
                       content에 하나라도 매칭되면 해당 파일을 DB 계층으로 분류.
    catch_all      : True → db_layer 클래스에서 SQL+동적결합 패턴을 함수명 무관하게 포착
    sink_patterns  : 명시적 Sink 패턴 목록 (dict; 아래 schema 참조)
    safe_binding_markers : 안전 바인딩 식별 정규식.
                           [!] 탐지 필터링 금지 — evidence 주석 전용.
    source_markers : HTTP 입력 어노테이션/패턴 (Source 식별)
    taint_suffixes : Taint 추적 컴포넌트 접미사 (Service, Repository 등)

    sink_pattern schema
    -------------------
    {
      "id":          str  — 룰 ID
      "name":        str  — 룰 이름
      "pattern":     str  — 정규식 (파일 내 줄 단위 매칭)
      "file_glob":   list[str] (optional, 미입력 시 lang_globs 사용)
      "file_content_check": str (optional) — 파일 전체에 이 패턴이 있어야 활성화
      "is_vulnerable": bool
      "access_type": str  — "raw_concat" | "bind" | "orm" | "mybatis_safe" | "mybatis_unsafe" | ...
      "detail":      str  — 진단 설명 (Korean)
      "context_check":    str (optional) — 매칭 줄 주변 N줄에서 이 패턴이 있어야 활성
      "context_window":   int (optional, default 5)
    }
    """
    framework_id:       str
    lang_globs:         list[str]
    db_layer_markers:   list[str]
    catch_all:          bool = True
    sink_patterns:      list[dict] = field(default_factory=list)
    safe_binding_markers: list[str] = field(default_factory=list)
    source_markers:     list[str] = field(default_factory=list)
    taint_suffixes:     list[str] = field(default_factory=list)

    # 컴파일된 캐시 (내부용 — 직접 접근 금지)
    _compiled_db_layer_list: list = field(
        default_factory=list, init=False, repr=False, compare=False)
    _compiled_safe_binding_list: list = field(
        default_factory=list, init=False, repr=False, compare=False)
    _db_layer_compiled: bool = field(
        default=False, init=False, repr=False, compare=False)
    _safe_binding_compiled: bool = field(
        default=False, init=False, repr=False, compare=False)

    def _ensure_db_layer_compiled(self):
        if not self._db_layer_compiled:
            compiled = []
            for m in self.db_layer_markers:
                # inline (?i) 플래그 제거 후 re.IGNORECASE 적용
                clean = re.sub(r'^\(\?[imsxu]+\)', '', m)
                compiled.append(re.compile(clean, re.IGNORECASE | re.DOTALL))
            object.__setattr__(self, '_compiled_db_layer_list', compiled)
            object.__setattr__(self, '_db_layer_compiled', True)

    def _ensure_safe_binding_compiled(self):
        if not self._safe_binding_compiled:
            compiled = []
            for m in self.safe_binding_markers:
                clean = re.sub(r'^\(\?[imsxu]+\)', '', m)
                compiled.append(re.compile(clean, re.IGNORECASE | re.DOTALL))
            object.__setattr__(self, '_compiled_safe_binding_list', compiled)
            object.__setattr__(self, '_safe_binding_compiled', True)

    def is_db_layer_class(self, content: str) -> bool:
        """content가 이 프레임워크의 DB 계층 클래스인지 확인."""
        if not self.db_layer_markers:
            return False
        self._ensure_db_layer_compiled()
        return any(p.search(content) for p in self._compiled_db_layer_list)

    def has_safe_binding(self, text: str) -> bool:
        """text 안에 안전 바인딩 패턴이 있는지 확인.
        [!] 탐지 필터에 사용 금지 — evidence 주석 전용.
        """
        if not self.safe_binding_markers:
            return False
        self._ensure_safe_binding_compiled()
        return any(p.search(text) for p in self._compiled_safe_binding_list)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Rule Registry
# ─────────────────────────────────────────────────────────────────────────────

RULE_REGISTRY: dict[str, FrameworkRule] = {}


def register_rule(rule: FrameworkRule) -> None:
    RULE_REGISTRY[rule.framework_id] = rule


def get_matching_rules(content: str, filename: str) -> list[FrameworkRule]:
    """content + filename에 해당하는 프레임워크 룰 목록 반환."""
    matched = []
    for rule in RULE_REGISTRY.values():
        # 파일 확장자 필터
        if rule.lang_globs:
            ext_ok = any(filename.endswith(g.replace("*", "")) for g in rule.lang_globs)
            if not ext_ok:
                continue
        if rule.is_db_layer_class(content):
            matched.append(rule)
    return matched


# ─────────────────────────────────────────────────────────────────────────────
# 3. Catch-All 탐지 공통 패턴
# ─────────────────────────────────────────────────────────────────────────────

# DB 계층 클래스에서 SQL 맥락 확인 (어떤 함수 안에서든 SQL이 있는지)
CATCH_ALL_SQL_KEYWORD_RE = re.compile(
    r'\b(?:SELECT|INSERT|UPDATE|DELETE|ALTER|TRUNCATE|DROP|CREATE|REPLACE)(?!\w)'  # 후방 경계 (?!\w): deleteXxx, createXxx 등 Java/Kotlin 메서드명 FP 방지
    r'(?:\s+\w+|\s+\*|\s+INTO|\s+FROM|\s+TABLE)?'
    r'|(?:FROM|WHERE|JOIN|GROUP\s+BY|ORDER\s+BY|HAVING|LIMIT|OFFSET|SET)\s+',
    re.IGNORECASE,
)

# 동적 문자열 결합/보간 패턴 (언어 무관)
CATCH_ALL_DYNAMIC_RE = re.compile(
    r'(?:'
    r'"[^"]*"\s*\+(?=\s*[^\s"\x27`])'  # "sql" + var  (Java/Kotlin/JS) — 다음이 또 다른 문자열 리터럴이면 제외(멀티라인 가독성 포맷 FP 방지)
    r'|"\s*\+\s*\w'          # " " + var
    r"|`[^`]*\$\{"           # `...${var}`   (Kotlin/JS template)
    r'|\w\s*\+\s*"[^"]*"'    # var + "sql"  — \w 필수로 문자열+문자열 패턴 제외(FP 방지)
    r'|\$\{[^}]+\}'          # ${var}        (Kotlin/Groovy/MyBatis unsafe)
    r'|%s|%d|%\([^)]+\)s'   # Python % format
    r'|\.format\s*\('        # .format(
    r'|f"[^"]*\{'            # Python f-string
    r'|buildString\s*\{'     # Kotlin buildString { append }
    r'|StringBuilder|StringBuffer'  # Java string builder
    r'|append\s*\('          # .append( on builder
    r'|\.concat\s*\('        # Java String.concat()
    r'|\.plus\s*\('          # Kotlin plus()
    r'|MessageFormat\.format\s*\('  # Java MessageFormat.format()
    r')',
    re.DOTALL,
)

# 안전한 바인딩 패턴 (Fail-Open 원칙: 필터링 금지, 주석만)
SAFE_BINDING_ANNOTATION_RE = re.compile(
    r'(?:'
    r'#\{[^}]+\}'                       # MyBatis #{param}
    r'|\.bind\s*\('                     # R2DBC .bind(
    r'|:\s*[a-zA-Z_]\w*\b'             # :namedParam
    r'|\?\s*[0-9]'                      # ?1 positional
    r'|setString\s*\('                  # JDBC setString
    r'|setInt\s*\(|setLong\s*\('       # JDBC setInt/setLong
    r'|PreparedStatement\b'             # PreparedStatement
    r')',
)


# ─────────────────────────────────────────────────────────────────────────────
# 4. 프레임워크별 룰 정의
# ─────────────────────────────────────────────────────────────────────────────

# ── 4-1. Spring JPA / Spring Data ────────────────────────────────────────────
register_rule(FrameworkRule(
    framework_id="spring_jpa",
    lang_globs=["*.kt", "*.java"],
    db_layer_markers=[
        r'\bJpaRepository\b',
        r'\bCrudRepository\b',
        r'\bPagingAndSortingRepository\b',
        r'\bQuerydslPredicateExecutor\b',
        r'EntityManager\b',
        r'createNativeQuery\s*\(',
        r'createQuery\s*\(',
        r'@Query\s*\(',
        r'@NamedQuery\b',
    ],
    catch_all=True,
    sink_patterns=[
        {
            "id": "JPA_QUERY_CONCAT",
            "name": "JPA @Query 문자열 결합",
            "pattern": r'@Query\s*\(\s*(?:value\s*=\s*)?["\'][\s\S]*?\+(?=\s*[^\s"\x27])',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "JPA @Query 어노테이션 내 문자열 결합으로 파라미터 직접 삽입",
            # 패턴 설명: + 뒤에 또 다른 문자열 리터럴(" 또는 ')이 오는 경우는 멀티라인 가독성 포맷 → 제외
        },
        {
            "id": "JPA_NATIVE_QUERY_CONCAT",
            "name": "EntityManager.createNativeQuery() 문자열 결합",
            "pattern": r'createNativeQuery\s*\(\s*.*?(?:\+|buildString|StringBuilder)',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "EntityManager.createNativeQuery()에 동적 쿼리 삽입",
        },
        {
            "id": "JPA_CREATE_QUERY_CONCAT",
            "name": "EntityManager.createQuery() 문자열 결합",
            "pattern": r'createQuery\s*\(\s*.*?(?:\+|buildString|StringBuilder)',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "EntityManager.createQuery() JPQL에 동적 삽입",
        },
    ],
    safe_binding_markers=[
        r':[a-zA-Z_]\w*\b',      # :namedParam
        r'\?[0-9]+',              # ?1 positional
        r'@Param\s*\(',           # @Param annotation
    ],
    source_markers=[
        r'@RequestParam\b', r'@PathVariable\b', r'@RequestBody\b',
        r'@ModelAttribute\b', r'getParameter\s*\(',
    ],
    taint_suffixes=["Repository", "Dao", "DAO"],
))


# ── 4-2. MyBatis / iBatis ────────────────────────────────────────────────────
register_rule(FrameworkRule(
    framework_id="mybatis",
    lang_globs=["*.kt", "*.java", "*.xml"],
    db_layer_markers=[
        r'@Mapper\b',
        r'\bSqlSession\b',
        r'\bSqlMapClient\b',
        r'\bsqlMapClientTemplate\b',
        r'\bsqlSessionTemplate\b',
        r'(?i)(?:ibatis|mybatis)',
        r'@(?:Select|Insert|Update|Delete)\s*\(',
        r'@SelectProvider\b|@UpdateProvider\b',
    ],
    catch_all=True,
    sink_patterns=[
        {
            "id": "MYBATIS_DOLLAR_XML",
            "name": "MyBatis XML ${} 문자열 보간",
            "pattern": r'\$\{[^}]+\}',
            "file_glob": ["*.xml"],
            "file_content_check": r'(?:<mapper\s+namespace\s*=|<!DOCTYPE\s+mapper|<resultMap\s)',
            "is_vulnerable": True,
            "access_type": "mybatis_unsafe",
            "detail": "MyBatis XML ${} — PreparedStatement 바인딩 없이 직접 문자열 치환",
        },
        {
            "id": "MYBATIS_DOLLAR_ANNOTATION",
            "name": "MyBatis 어노테이션 ${} 문자열 보간",
            "pattern": r'@(?:Select|Insert|Update|Delete)\s*\(\s*["\'].*?\$\{',
            "file_glob": ["*.kt", "*.java"],
            "is_vulnerable": True,
            "access_type": "mybatis_unsafe",
            "detail": "MyBatis 어노테이션 ${} — SQL Injection",
        },
        {
            "id": "MYBATIS_DYNAMIC_SQL_CONCAT",
            "name": "MyBatis 동적 SQL 문자열 결합",
            "pattern": r'(?:sqlSession|session)\.(?:selectList|selectOne|insert|update|delete)\s*\(\s*.*?".*?\+',
            "file_glob": ["*.kt", "*.java"],
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "SqlSession 직접 호출 + 문자열 결합 — SQL Injection",
        },
    ],
    safe_binding_markers=[r'#\{[^}]+\}'],
    source_markers=[
        r'@RequestParam\b', r'@PathVariable\b', r'@RequestBody\b',
        r'getParameter\s*\(',
    ],
    taint_suffixes=["Mapper", "Dao", "DAO"],
))


# ── 4-3. Spring Data R2DBC / Reactive ────────────────────────────────────────
register_rule(FrameworkRule(
    framework_id="r2dbc",
    lang_globs=["*.kt", "*.java"],
    db_layer_markers=[
        r'\bDatabaseClient\b',
        r'\bR2dbcEntityTemplate\b',
        r'\bReactiveCrudRepository\b',
        r'\bR2dbcRepository\b',
        r'\bCoroutineCrudRepository\b',
        r'\bCoroutineRepository\b',
        r'\bReactiveSortingRepository\b',
        r'\bReactiveMongoRepository\b',
        r'(?i)r2dbc',
    ],
    catch_all=True,
    sink_patterns=[
        {
            "id": "R2DBC_SQL_CONCAT",
            "name": "R2DBC DatabaseClient SQL 문자열 결합",
            "pattern": r'\.(?:sql|execute)\s*\(\s*(?:"[^"]*"\s*\+|\w[^)]*\+)',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "DatabaseClient.sql()/execute() — 문자열 결합으로 파라미터 직접 삽입",
        },
        {
            "id": "R2DBC_SQL_VAR",
            "name": "R2DBC DatabaseClient 동적 변수 SQL",
            "pattern": r'\.(?:sql|execute)\s*\(\s*([a-zA-Z_]\w*)\s*\)',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "DatabaseClient.sql(변수) — 동적 변수 삽입 (바인딩 확인 필요)",
        },
        {
            "id": "R2DBC_CRITERIA_TOSTRING",
            "name": "R2DBC Criteria.toString() SQL 직접 삽입",
            "pattern": r'(?:Criteria\.where|criteria|definition).*?\.toString\s*\(\)',
            "is_vulnerable": True,
            "access_type": "criteria_tosql",
            "detail": "Criteria.toString()으로 SQL WHERE절 직접 삽입",
        },
        {
            "id": "R2DBC_BUILDSTRING_SQL",
            "name": "R2DBC buildString SQL 동적 생성",
            "pattern": r'(?:buildString|StringBuilder|StringBuffer)\s*(?:\{|\()',
            "context_check": r'(?:\.sql\s*\(|\.execute\s*\(|SELECT|INSERT|UPDATE|DELETE|_SQL\b)',
            "context_window": 8,
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "buildString/StringBuilder로 SQL 동적 구성",
        },
    ],
    safe_binding_markers=[
        r'\.bind\s*\(',
        r':\s*[a-zA-Z_]\w*\b',   # :namedParam
    ],
    source_markers=[
        r'@RequestParam\b', r'@PathVariable\b', r'@RequestBody\b',
    ],
    taint_suffixes=["Repository", "Dao"],
))


# ── 4-4. JDBC (classic Spring JDBC / raw JDBC) ───────────────────────────────
register_rule(FrameworkRule(
    framework_id="jdbc",
    lang_globs=["*.kt", "*.java"],
    db_layer_markers=[
        r'\bJdbcTemplate\b',
        r'\bNamedParameterJdbcTemplate\b',
        r'\bSimpleJdbcCall\b',
        r'\bSimpleJdbcInsert\b',
        r'Statement\.execute(?:Query|Update)',
        r'conn\.prepareStatement\b',
        r'getConnection\s*\(\s*\)',
    ],
    catch_all=True,
    sink_patterns=[
        {
            "id": "JDBC_STATEMENT_CONCAT",
            "name": "JDBC Statement 직접 실행 (문자열 결합)",
            "pattern": r'(?:Statement|stmt|stm)\.execute(?:Query|Update|Batch)?\s*\(\s*(?:[a-zA-Z_]\w*\s*\+|"[^"]*"\s*\+)',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "Statement.executeQuery/executeUpdate — 문자열 결합으로 SQL Injection",
        },
        {
            "id": "JDBC_TEMPLATE_CONCAT",
            "name": "JdbcTemplate 동적 SQL (문자열 결합)",
            "pattern": r'(?:jdbcTemplate|jdbc)\.(?:query|update|execute|queryForList|queryForObject)\s*\(\s*(?:[a-zA-Z_]\w*\s*\+|"[^"]*"\s*\+)',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "JdbcTemplate — 동적 SQL 문자열 결합으로 SQL Injection",
        },
    ],
    safe_binding_markers=[
        r'PreparedStatement\b',
        r'setString\s*\(|setInt\s*\(|setLong\s*\(|setObject\s*\(',
        r':\s*[a-zA-Z_]\w*\b',   # NamedParameterJdbcTemplate :param
    ],
    source_markers=[
        r'@RequestParam\b', r'@PathVariable\b', r'getParameter\s*\(',
    ],
    taint_suffixes=["Repository", "Dao", "DAO"],
))


# ── 4-5. Node.js (pg / mysql / mysql2 / knex / sequelize / typeorm) ──────────
register_rule(FrameworkRule(
    framework_id="nodejs",
    lang_globs=["*.js", "*.ts", "*.mjs", "*.cjs", "*.jsx", "*.tsx"],
    db_layer_markers=[
        r'(?:db|client|pool|connection)\.query\s*\(',
        r'\bSequelize\b',
        r'\bKnex\b',
        r'\bPrisma\b(?:Client)?',
        r'\bTypeORM\b|getRepository\s*\(',
        r'(?:require|import).*?(?:"pg"|"mysql"|"mysql2"|"sqlite3"|"mssql")',
        r'(?:require|import).*?(?:"knex"|"sequelize"|"typeorm")',
        r'createConnection\s*\(|createPool\s*\(',
    ],
    catch_all=True,
    sink_patterns=[
        {
            "id": "NODEJS_SQL_CONCAT",
            "name": "Node.js SQL 문자열 결합/보간",
            "pattern": r'(?:db|client|connect|pool|connection)\.query\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*"\s*\+)',
            "file_glob": ["*.js", "*.ts", "*.mjs", "*.cjs"],
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "Node.js db.query() — 템플릿 리터럴/문자열 결합으로 SQL Injection",
        },
        {
            "id": "NODEJS_KNEX_RAW_CONCAT",
            "name": "Knex raw() 문자열 결합",
            "pattern": r'knex\.raw\s*\(\s*(?:`[^`]*\$\{|"[^"]*"\s*\+)',
            "file_glob": ["*.js", "*.ts"],
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "Knex.raw() — 동적 SQL 삽입",
        },
        {
            "id": "NODEJS_SEQUELIZE_LITERAL_CONCAT",
            "name": "Sequelize literal() 동적 SQL",
            "pattern": r'Sequelize\.literal\s*\(\s*(?:`[^`]*\$\{|"[^"]*"\s*\+)',
            "file_glob": ["*.js", "*.ts"],
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "Sequelize.literal() — 동적 SQL Injection",
        },
    ],
    safe_binding_markers=[
        r'\?\s*,',            # pg/mysql positional ?
        r'\$[0-9]+',          # pg $1 $2
        r'replacements\s*:',  # Sequelize named replacements
    ],
    source_markers=[
        r'req\.(?:body|query|params)\b',
        r'request\.(?:body|query|params)\b',
        r'ctx\.(?:request|query|params)\b',   # Koa
    ],
    taint_suffixes=["Repository", "Dao", "Service"],
))


# ── 4-6. Python (SQLAlchemy / psycopg2 / sqlite3 / Django ORM) ───────────────
register_rule(FrameworkRule(
    framework_id="python_db",
    lang_globs=["*.py"],
    db_layer_markers=[
        r'(?:import|from)\s+(?:sqlalchemy|psycopg2|pymysql|sqlite3|django\.db)',
        r'cursor\.execute\s*\(',
        r'session\.execute\s*\(',
        r'connection\.execute\s*\(',
        r'db\.execute\s*\(',
        r'Base\.metadata\b',
        r'Model\.objects\.',
        r'text\s*\(',             # SQLAlchemy text()
    ],
    catch_all=True,
    sink_patterns=[
        {
            "id": "PYTHON_SQL_FORMAT",
            "name": "Python SQL % 또는 f-string 포맷",
            "pattern": r'(?:cursor|session|connection|db|conn)\.execute\s*\(\s*(?:"[^"]*%[sd]|f"[^"]*\{|"[^"]*"\s*%\s*)',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "Python execute() — % 포맷/f-string으로 SQL Injection",
        },
        {
            "id": "PYTHON_SQL_CONCAT",
            "name": "Python SQL 문자열 결합",
            "pattern": r'(?:cursor|session|connection|db|conn)\.execute\s*\(\s*(?:"[^"]*"\s*\+|sql\s*\+)',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "Python execute() — 문자열 결합으로 SQL Injection",
        },
        {
            "id": "PYTHON_SQLALCHEMY_TEXT_CONCAT",
            "name": "SQLAlchemy text() 동적 SQL",
            "pattern": r'text\s*\(\s*(?:"[^"]*"\s*\+|f"[^"]*\{|"[^"]*%[sd])',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "SQLAlchemy text() — 동적 SQL 조합 (bindparams 사용 필요)",
        },
    ],
    safe_binding_markers=[
        r'bindparams\s*\(',   # SQLAlchemy
        r'%s\b',              # psycopg2 parameterized (safe — placeholder)
        r'\?\s',              # sqlite3 parameterized
    ],
    source_markers=[
        r'request\.(?:GET|POST|args|form|json)\b',
        r'flask\.request\b',
        r'django\.http\.HttpRequest\b',
    ],
    taint_suffixes=["Repository", "Dao", "View", "Service"],
))


# ── 4-7. PHP ──────────────────────────────────────────────────────────────────
register_rule(FrameworkRule(
    framework_id="php",
    lang_globs=["*.php"],
    db_layer_markers=[
        r'(?:mysqli|PDO|mysql_query)\b',
        r'\$(?:db|conn|pdo|mysqli)\s*->',
        r'new\s+PDO\s*\(',
        r'mysql_connect\s*\(',
    ],
    catch_all=True,
    sink_patterns=[
        {
            "id": "PHP_SQL_CONCAT",
            "name": "PHP SQL 문자열 결합",
            "pattern": r'(?:mysqli_query|mysql_query|\$(?:db|conn|pdo|mysqli)->query)\s*\(\s*(?:[^,]+\.|\$[a-zA-Z_]\w*\s*\.\s*)',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "PHP query() — 문자열 결합으로 SQL Injection",
        },
        {
            "id": "PHP_SQL_INTERP",
            "name": "PHP SQL 변수 보간",
            "pattern": r'(?:mysqli_query|mysql_query|\$(?:db|conn)->query)\s*\(\s*["\'].*?\$[a-zA-Z_]',
            "is_vulnerable": True,
            "access_type": "raw_concat",
            "detail": "PHP query() — 문자열 내 변수 보간으로 SQL Injection",
        },
    ],
    safe_binding_markers=[
        r'prepare\s*\(',
        r'bindParam\s*\(|bindValue\s*\(',
        r'execute\s*\(\s*\[',   # PDO execute with array
    ],
    source_markers=[r'\$_(?:GET|POST|REQUEST|COOKIE)\b'],
    taint_suffixes=["Repository", "Dao"],
))


# ── 4-8. Kotlin / Java 범용 SQL Builder Catch-All ────────────────────────────
# (앞의 프레임워크-특화 룰에서 미처 잡지 못한 사내 래핑 클래스 대응)
register_rule(FrameworkRule(
    framework_id="kotlin_java_generic",
    lang_globs=["*.kt", "*.java"],
    db_layer_markers=[
        # DAO/Repository/Mapper 계층 명명 관례
        r'(?:class|object)\s+\w+(?:Dao|DAO|Repository|Mapper|Store|Gateway)\b',
        r'@Repository\b',
        r'@Dao\b',              # Room (Android)
        r'\bDao\b|\bMapper\b',  # 인터페이스 이름에 포함
    ],
    catch_all=True,  # 명시적 sink_patterns 없이 Catch-All만 사용
    sink_patterns=[],
    safe_binding_markers=[
        r'#\{[^}]+\}',
        r'\.bind\s*\(',
        r':\s*[a-zA-Z_]\w*\b',
        r'PreparedStatement\b',
    ],
    taint_suffixes=["Repository", "Dao", "DAO", "Mapper", "Store"],
))


# ─────────────────────────────────────────────────────────────────────────────
# 5. Source (HTTP 입력) 공통 마커 — 엔진 레이어 참조용
# ─────────────────────────────────────────────────────────────────────────────

# Spring / JVM 계열 HTTP 파라미터 어노테이션
JVM_SOURCE_MARKERS = [
    r'@RequestParam\b',
    r'@PathVariable\b',
    r'@RequestBody\b',
    r'@ModelAttribute\b',
    r'@RequestPart\b',
    r'getParameter\s*\(',
    r'HttpServletRequest\b',
    r'ServerWebExchange\b',
    r'ServerRequest\b',     # WebFlux RouterFunction
]

# Spring Controller 계층 어노테이션
JVM_CONTROLLER_MARKERS = [
    r'@RestController\b',
    r'@Controller\b',
    r'@RequestMapping\b',
    r'@GetMapping\b|@PostMapping\b|@PutMapping\b|@DeleteMapping\b|@PatchMapping\b',
    r'RouterFunction\b',    # WebFlux functional router
]

# Taint 추적 컴포넌트 접미사 (엔진에서 Controller→Service 위임 추적에 사용)
TAINT_COMPONENT_SUFFIXES = (
    'Service', 'UseCase', 'Handler', 'Adapter', 'Facade',
    'Provider', 'Helper', 'Processor', 'Manager', 'Delegate',
    'Component', 'Coordinator', 'Port',
)


# ─────────────────────────────────────────────────────────────────────────────
# 6. 헬퍼: Catch-All 동적 SQL 탐지 (엔진 내 _catch_all_db_sink_scan 에서 호출)
# ─────────────────────────────────────────────────────────────────────────────

def detect_dynamic_sql_in_body(method_body: str) -> list[dict]:
    """메서드 본문에서 SQL 키워드 + 동적 결합 패턴을 탐지한다.

    함수명·프레임워크 무관하게 탐지 (Catch-All).
    반환:
        [{"line_no": int, "snippet": str, "has_safe_binding": bool}, ...]
    """
    results = []
    lines = method_body.splitlines()
    for idx, line in enumerate(lines, start=1):
        # (a) 동적 결합 패턴이 있고
        if not CATCH_ALL_DYNAMIC_RE.search(line):
            continue
        # (b) SQL 키워드 컨텍스트 확인 (±5줄)
        window_start = max(0, idx - 6)
        window_end   = min(len(lines), idx + 5)
        window_text  = "\n".join(lines[window_start:window_end])
        if not CATCH_ALL_SQL_KEYWORD_RE.search(window_text):
            continue
        # (c) 안전 바인딩 주석 (필터링 금지!)
        has_safe = bool(SAFE_BINDING_ANNOTATION_RE.search(window_text))
        results.append({
            "line_no":         idx,
            "snippet":         line.strip(),
            "has_safe_binding": has_safe,
        })
    return results
