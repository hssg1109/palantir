# Secret Scanning

Primary tool: **scan_data_protection.py 내장 패턴 탐지**

`scan_data_protection.py`의 `_redact_snippet()` 함수가 Secrets 카테고리 code_snippet 생성 시 자동으로 자격증명 값을 `[REDACTED]`로 마스킹한다.

```
password=abc123  →  password=[REDACTED]
secret=my-key   →  secret=[REDACTED]
jdbc:mysql://host/db  →  jdbc:mysql://[REDACTED_JDBC_URL]
192.168.1.1     →  [REDACTED_IP]
```

마스킹 패턴 (`_REDACT_SECRET_VALUE_RE`):
- `password`, `passwd`, `pwd`, `secret`, `token`, `apikey`, `api-key`, `accesskey`, `access-key`, `secretkey`, `secret-key`, `client-secret`, `private-key`, `signing-key`, `hmac-key`, `auth-key`, `username`, `user-name`, `account`, `user`, `account-id`

> **참고**: gitleaks는 현재 워크플로에서 사용하지 않는다.  
> scan_data_protection.py 내장 탐지로 충분하며, 별도 외부 툴 설치·실행 불필요.
