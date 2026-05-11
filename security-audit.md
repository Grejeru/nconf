# NConf Security Audit

**Date:** 2026-05-11  
**Auditor:** Claude Opus 4.7 (319K tokens, 83 files read)  
**Branch:** feature/sky-adjustments  
**Already fixed:** SQL injection (`d01d989`), path traversal in static_file_editor (`daf69ee`)

---

## Summary

| Severity | Count |
|----------|------:|
| CRITICAL | 14 |
| HIGH | 30 |
| MEDIUM | 22 |
| LOW | 7 |
| **Total** | **73** |

---

## Remediation Plan (Priority Order)

### P1 — Fix immediately (pre-auth / unauthenticated attack surface)

- [ ] **SQLi in SQL auth** — `include/login_check.php:167-172`  
  `!!!USERNAME!!!`/`!!!PASSWORD!!!` str_replace'd unescaped into `AUTH_SQLQUERY_USER/ADMIN`. Pre-auth bypass.  
  Fix: `escape_string()` both vars before str_replace, or use prepared statements.

- [ ] **SQLi in history_add()** — `include/functions.php:322`  
  `$user` (raw `$_POST["username"]` on failed login) interpolated into INSERT. Pre-auth.  
  Fix: escape_string all 4 interpolated vars in history_add().

- [ ] **Unauthenticated command injection** — `ADD-ONS/incoming_config.php`  
  No auth whatsoever. Uploaded filename used in `exec(escapeshellcmd(...))`. Also `$_POST["remote_execute"]` triggers `exec()`.  
  Fix: Add shared-secret token auth; use `escapeshellarg()` per argument; block web access if not needed.

- [ ] **Auth bypass via dependency.php nagiosview** — `dependency.php:133-187`  
  `?xmode=nagiosview` loads `main.php` instead of `head.php` — skips login_check entirely. Exposes full host/topology data.  
  Fix: Add auth check before branching on xmode.

- [ ] **Session identity spoofing** — `call_file.php:38-44`  
  `$_REQUEST["username"]` overwrites `$_SESSION["userinfos"]["username"]`. Any user can impersonate anyone in history logs.  
  Fix: Remove entirely — username must only come from session set at login.

### P2 — SQL injection sweep (authenticated but exploitable by any logged-in user)

- [ ] **handle_item.php** — `$_GET["id"]` and `$_GET["xmode"]` raw in queries (lines 99-107, 125-131, 144-149, 159-166, 716-720, 728-732, 815-823, 845-852, 981-989, 1009-1017)
- [ ] **delete_item.php / delete_attr.php / delete_class.php** — `$_POST["id"]`/`$_POST["ids"]` raw in DELETE statements — `1 OR 1=1` deletes all rows
- [ ] **clone_host_write2db.php** — `$_POST["hostname"]`, `["alias"]`, `["ip"]`, `["parents"]` raw in INSERT (lines 17, 80-82, 102, 124-128, 161, 177-180, 187-194, 211-215, 228, 241, 273-274, 295, 301)
- [ ] **modify_attr_write2db.php** — nearly every `$_POST` field raw in INSERT/UPDATE (lines 27, 37, 57-58, 62, 144-160, 166-168, 183-184, 276, 279-292)
- [ ] **modify_class_write2db.php** — all POST fields raw in UPDATE/INSERT (lines 9-15, 19, 60, 90-91, 97-111)
- [ ] **include/ajax/json/history.php** — `$_GET["id"]` raw in query (line 8); also leaks SQL query+error in die()
- [ ] **include/ajax/service_clone.php**, **service_add.php**, **advanced_service.php**, **service_list.php** — multiple raw POST/GET in INSERT/SELECT
- [ ] **dependency.php** — `$_GET["id"]` raw in queries (lines 31, 117-119, 267, 286)
- [ ] **modify_attr.php:13,23** and **modify_class.php:13,22** — `$_GET["id"]` raw in SELECT
- [ ] **show_attr.php:133-138** / **show_class.php:40-47** — `$_GET["id"]` in ORDER functions
- [ ] **db_templates() ORDER BY** — `include/functions.php:786-819` — `$search` used in `ORDER BY $search`; not safe to escape, must whitelist

  **Global fix pattern:**
  ```php
  // integers
  $id = (int)$_GET["id"];
  // strings
  $val = escape_string($_POST["fieldname"]);
  // enum-like (datatype, mandatory, visible, etc.)
  $allowed = ["yes","no"]; $val = in_array($val, $allowed) ? $val : "no";
  ```

### P3 — CSRF protection

- [ ] Generate CSRF token on session start, store in `$_SESSION["csrf_token"]`
- [ ] Add hidden `<input type="hidden" name="csrf_token" value="...">` to all forms
- [ ] Validate on every POST: `if ($_POST["csrf_token"] !== $_SESSION["csrf_token"]) die(403)`
- [ ] Also add to logout (currently GET-based — trivially triggerable via `<img src="...?logout=1">`)

  Affects: all `*_write2db.php`, `delete_*.php`, `static_file_editor.php`, `handle_item.php`, login form

### P4 — XSS sweep

Every `$_GET`/`$_POST`/`$_SESSION`/`$_SERVER` value and DB-sourced string echoed to HTML needs wrapping:
```php
htmlspecialchars($value, ENT_QUOTES, 'UTF-8')
```

Key locations:
- [ ] `include/head.php:176` — welcome username (`$_SESSION["userinfos"]["username"]`)
- [ ] `overview.php:215,218,222,225,233,275,295,308-318,627-638,830-834,895-906` — filter/class/order/entryname/request_url
- [ ] `detail.php:73,80-90,132-133` — item_class, item_name, icon_image (stored XSS via `<img src=...>`)
- [ ] `history.php:24` / `include/ajax/json/history.php:142-179` — `$_GET["id"]` echoed into JS string; DB row values in `<a>` tags
- [ ] `id_wrapper.php:14,27,44-45` — `$_GET["item"]` in error message, meta refresh URL
- [ ] `include/login_form.php:40,81` — `$url` (goto param) as form action
- [ ] `include/head.php:303-306` — `$_SERVER["REQUEST_URI"]` in meta refresh
- [ ] `static_file_editor.php:168,186-208,234,244` — request_url, config_dir, config_filename, file_content in textarea
- [ ] `modify_item_write2db.php:88-89,143,255` — config_class, `$_SERVER["PHP_SELF"]` as form action
- [ ] `multimodify_attr_write2db.php:288,296,308,310,313,325-328` — POST values + PHP_SELF
- [ ] `clone_host.php:51,56,61,78,84,102-107` — session cache values, DB attr_value
- [ ] `show_attr.php`, `show_class.php`, `detail_admin_items.php` — class param, DB values in TD/option

  Special cases:
  - `$_SERVER["PHP_SELF"]` as form action → replace with hardcoded script name
  - `$_SERVER["HTTP_REFERER"]` stored in `$_SESSION["after_delete_page"]` → validate same-origin before storing

### P5 — Session & authentication hardening

- [ ] **Session fixation** — add `session_regenerate_id(true)` immediately after successful login in all auth branches (`include/login_check.php` file/sql/ldap/ad_ldap paths)
- [ ] **Session cookies** — add to `main.php` or early boot:
  ```php
  ini_set('session.cookie_httponly', '1');
  ini_set('session.cookie_samesite', 'Lax');
  ini_set('session.cookie_secure', '1');  // when HTTPS
  ini_set('session.use_strict_mode', '1');
  ```
- [ ] **LDAP anonymous bind** — `include/login_check.php:204,288` — reject empty/whitespace password before `ldap_bind()`; sanitize `$user_loginname` with `ldap_escape()` for both DN and filter contexts
- [ ] **Password hashing** — `include/functions.php:1582-1631` — replace `encrypt_password()` with `password_hash()`/`password_verify()` (PHP 5.5+, available on 7.4). Mark legacy hashes for re-hash on next login.
- [ ] **Open redirect** — `include/login_form.php:18-40` — validate `$_GET["goto"]` against same-origin whitelist pattern `^[A-Za-z0-9._\-/?&=]+$`

### P6 — Privilege escalation & IDOR

- [ ] **Privilege escalation via client-controlled ID_nc_permission** — `add_item_step2.php:15-26`  
  Server must look up nc_permission attr ID from DB, not trust `$_POST["ID_nc_permission"]`

- [ ] **IDOR — incomplete permission check** — `include/classes/class.NConf_PERMISSIONS.php:55-90`  
  `checkIdPermission()` only checks `$_REQUEST["id"]`/`$_REQUEST["ids"]`. Calls with other param names (HIDDEN_modify_id, template_id, service_id, source_host_id, host_id) bypass the check entirely.  
  Fix: Call `checkIdPermission()` for every item-id parameter in each write endpoint.

- [ ] **static_file_editor.php missing explicit admin check** — add at top:
  ```php
  if (!isset($_SESSION["group"]) || $_SESSION["group"] !== GROUP_ADMIN) {
      http_response_code(403); exit;
  }
  ```

### P7 — Command injection in deployment

- [ ] **rsync/scp/ssh module** — `include/modules/deployment/rsync/class.deployment_rsync.php`, `scp/class.deployment_scp.php`  
  `escapeshellcmd()` on assembled string is insufficient. Replace with `escapeshellarg()` on each individual argument value from `$host_infos`.

- [ ] **exec_generate_config.php** — lines 54, 117-119, 146-157, 174, 225-228, 270  
  `system()` calls with DB-sourced `$servers` array. Whitelist `$server` to `^[A-Za-z0-9._-]+$`; use `escapeshellarg()` per value.

- [ ] **Deployment module whitelist** — `class.deployment.php:97-111`  
  `new $module_name` from filesystem dir name. Whitelist to `['local','rsync','scp','http']`.

### P8 — Information disclosure

- [ ] **mysql_error() in die()** — `include/ajax/json/history.php:85,90,100`; `include/functions.php:1132`  
  Remove SQL query and `mysql_error()` from user-facing die() output. Log server-side only.

- [ ] **Default credentials** — `config.orig/.file_accounts.php` (admin::nconf), `config.orig/mysql.php` (link2db)  
  Block startup if defaults unchanged. Force first-run password change.

- [ ] **Version on login page** — `include/login_form.php:30-31` — remove `echo VERSION_STRING` from unauthenticated page.

- [ ] **DEBUG_MODE in prod** — `config/nconf.php` — ensure `DEBUG_MODE=0`; SQL queries must never reach UI.

- [ ] **SSL verification disabled in HTTP deployment** — `include/modules/deployment/http/class.deployment_http.php:20-21`  
  `CURLOPT_SSL_VERIFYPEER=0` + `CURLOPT_SSL_VERIFYHOST=0`. Default to on.

### P9 — Low priority / hardening

- [ ] No rate limiting on login — add per-IP/user failure counter
- [ ] Weak salt RNG — `genSalt()` uses `srand(microtime()*1e6)` — replace with `random_bytes()`
- [ ] Lock file race in `generate_config.php` — use `fopen($lock_file, 'x')` for atomic create
- [ ] `UPDATE_/` scripts should be outside webroot or blocked by web server
- [ ] Remove `@` error suppression; use proper try/catch and server-side logging

---

## Most Vulnerable Files (quick reference)

| File | Issues |
|------|--------|
| `include/login_check.php` | CRITICAL pre-auth SQLi, LDAP bypass/injection, session fixation, weak passwords |
| `ADD-ONS/incoming_config.php` | CRITICAL unauth command injection (2 paths) |
| `include/functions.php` | CRITICAL SQLi in history_add, weak crypto |
| `clone_host_write2db.php` | CRITICAL SQLi (5+ queries) |
| `modify_attr_write2db.php` | CRITICAL SQLi all writes |
| `modify_class_write2db.php` | CRITICAL SQLi all writes |
| `delete_item/attr/class.php` | CRITICAL SQLi destructive deletes |
| `handle_item.php` | CRITICAL SQLi many queries |
| `include/ajax/json/history.php` | CRITICAL SQLi + schema disclosure |
| `call_file.php` | HIGH session spoofing, path traversal |
| `include/modules/deployment/` | HIGH command injection |
| `overview.php` | HIGH XSS (multiple) |
| `dependency.php` | HIGH unauth access + SQLi |
