use std::io::{BufRead, BufReader};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_SANDBOX_ID: AtomicU64 = AtomicU64::new(0);
static CALLBACK_PORT_SETUP: Mutex<()> = Mutex::new(());

struct Sandbox(PathBuf);

struct PendingLogin {
    child: Child,
    callback_port: u16,
    state: String,
    request: thread::JoinHandle<String>,
    stderr_reader: thread::JoinHandle<String>,
}

impl Sandbox {
    fn at(path: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir(&path)?;
        std::fs::create_dir(path.join("sparebank1-cli"))?;
        Ok(Self(path))
    }

    fn new() -> Self {
        loop {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let id = NEXT_SANDBOX_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("sb1-profiles-{}-{nonce}-{id}", std::process::id()));
            match Self::at(path) {
                Ok(sandbox) => return sandbox,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("creating test sandbox: {error}"),
            }
        }
    }

    fn store(&self) -> PathBuf {
        self.0.join("sparebank1-cli")
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sb1"));
        command
            .args(args)
            .env("SB1_STORE", "file")
            .env("XDG_CONFIG_HOME", &self.0);
        command
    }

    fn configured_pair(&self) {
        let registry = r#"{"defaultProfile":"alice","profiles":[{"name":"alice","legacy":false},{"name":"bob","legacy":false}]}"#;
        std::fs::write(self.store().join("profiles.json"), registry).unwrap();
        for (name, token) in [("alice", "alice-token"), ("bob", "bob-token")] {
            let encoded: String = name.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            let credentials =
                format!(r#"{{"client_id":"{name}-id","client_secret":"{name}-secret"}}"#);
            let token = format!(
                r#"{{"access_token":"{token}","refresh_token":"{name}-refresh","expires_at":4102444800}}"#
            );
            std::fs::write(
                self.store()
                    .join(format!("profile-{encoded}-client-credentials.json")),
                credentials,
            )
            .unwrap();
            std::fs::write(
                self.store()
                    .join(format!("profile-{encoded}-oauth-token.json")),
                token,
            )
            .unwrap();
        }
    }
}

#[test]
fn sandbox_creation_refuses_to_reuse_an_existing_directory() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sb1-profiles-collision-{}-{nonce}",
        std::process::id()
    ));
    let first = Sandbox::at(path.clone()).unwrap();
    let second = Sandbox::at(path);
    assert!(matches!(second, Err(ref error) if error.kind() == std::io::ErrorKind::AlreadyExists));
    drop(first);
}

fn fake_bank_once(reply: &'static str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("fake bank received no request: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&request);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|n| n.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if body.len() >= length {
                    break;
                }
            }
        }
        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}", reply.len());
        stream.write_all(response.as_bytes()).unwrap();
        String::from_utf8(request).unwrap()
    });
    (url, handle)
}

fn fake_bank_sequence(
    replies: &'static [&'static str],
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for reply in replies {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("fake bank received fewer requests than expected: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 4096];
            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&request);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|line| {
                            let lower = line.to_ascii_lowercase();
                            lower
                                .strip_prefix("content-length: ")
                                .and_then(|n| n.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
            }
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}", reply.len());
            stream.write_all(response.as_bytes()).unwrap();
            requests.push(String::from_utf8(request).unwrap());
        }
        requests
    });
    (url, handle)
}

fn login_new_profile(
    sandbox: &Sandbox,
    name: &str,
    client_id: &str,
    client_secret: &str,
) -> Output {
    let (output, request) = finish_login(start_profile_login(
        sandbox,
        name,
        client_id,
        client_secret,
        r#"{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}"#,
    ));
    assert!(request.contains(client_id));
    assert!(request.contains(client_secret));
    output
}

fn start_profile_login(
    sandbox: &Sandbox,
    name: &str,
    client_id: &str,
    client_secret: &str,
    token_reply: &'static str,
) -> PendingLogin {
    begin_login(
        sandbox,
        vec![
            "login".to_owned(),
            "--profile".to_owned(),
            name.to_owned(),
            "--client-id".to_owned(),
            client_id.to_owned(),
            "--client-secret".to_owned(),
            client_secret.to_owned(),
        ],
        Some(b"yes\n"),
        token_reply,
    )
}

fn perform_login(sandbox: &Sandbox, args: Vec<String>, answer: Option<&[u8]>) -> (Output, String) {
    finish_login(begin_login(
        sandbox,
        args,
        answer,
        r#"{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}"#,
    ))
}

fn begin_login(
    sandbox: &Sandbox,
    mut args: Vec<String>,
    answer: Option<&[u8]>,
    token_reply: &'static str,
) -> PendingLogin {
    // Keep other login tests from selecting the same ephemeral callback port
    // while this child starts and binds its listener. The lock is released as
    // soon as the child prints its authorize URL, which follows the bind.
    let callback_port_setup = CALLBACK_PORT_SETUP.lock().unwrap();
    let (url, request) = fake_bank_once(token_reply);
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let redirect = format!("http://localhost:{port}/callback");
    args.extend(["--redirect-uri".to_owned(), redirect]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut child = sandbox
        .command(&args)
        .env("SB1_TEST_API_BASE_URL", url)
        .env("SB1_TEST_NO_BROWSER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(answer) = answer {
        child.stdin.take().unwrap().write_all(answer).unwrap();
    } else {
        drop(child.stdin.take());
    }
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let (url_tx, url_rx) = std::sync::mpsc::channel();
    let stderr_reader = thread::spawn(move || {
        let mut captured = String::new();
        loop {
            let mut line = String::new();
            match stderr.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if (line.trim().starts_with("http://") || line.trim().starts_with("https://"))
                        && url_tx.send(line.trim().to_owned()).is_err()
                    {
                        break;
                    }
                    captured.push_str(&line);
                }
            }
        }
        captured
    });
    let authorize_url = url_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("login exited before showing authorization URL"));
    let authorize = url::Url::parse(&authorize_url).unwrap();
    assert_eq!(authorize.path(), "/oauth/authorize");
    let state = authorize
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    drop(callback_port_setup);
    PendingLogin {
        child,
        callback_port: port,
        state,
        request,
        stderr_reader,
    }
}

fn finish_login(login: PendingLogin) -> (Output, String) {
    let mut callback = std::net::TcpStream::connect(("127.0.0.1", login.callback_port)).unwrap();
    write!(callback, "GET /callback?code=fake-code&state={} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", login.state).unwrap();
    let mut callback_response = Vec::new();
    let read_result = callback.read_to_end(&mut callback_response);
    assert!(
        read_result.is_ok()
            || read_result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset
    );
    assert!(callback_response.starts_with(b"HTTP/1.1 200 OK"));
    let output = login.child.wait_with_output().unwrap();
    let mut combined_stderr = login.stderr_reader.join().unwrap();
    combined_stderr.push_str(&String::from_utf8_lossy(&output.stderr));
    let token_request = login.request.join().unwrap_or_else(|_| {
        panic!(
            "fake bank received no token request; exit status: {}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            combined_stderr
        )
    });
    assert!(token_request.starts_with("POST /oauth/token "));
    (
        Output {
            stderr: combined_stderr.into_bytes(),
            ..output
        },
        token_request,
    )
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn status_adopts_legacy_login_without_moving_its_secrets() {
    let sandbox = Sandbox::new();
    let credentials = r#"{"client_id":"legacy-id","client_secret":"legacy-secret","redirect_uri":"http://localhost:12345/callback"}"#;
    let token = r#"{"access_token":"legacy-token","refresh_token":"legacy-refresh","token_type":"Bearer","expires_at":4102444800}"#;
    std::fs::write(sandbox.store().join("client-credentials.json"), credentials).unwrap();
    std::fs::write(sandbox.store().join("oauth-token.json"), token).unwrap();

    let result = sandbox.run(&["--json", "status"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(body["defaultProfile"], "default");
    assert_eq!(body["profiles"][0]["name"], "default");
    assert_eq!(body["profiles"][0]["tokenValid"], true);
    assert_eq!(body["profiles"][0]["legacyContext"], true);
    assert_eq!(
        std::fs::read_to_string(sandbox.store().join("client-credentials.json")).unwrap(),
        credentials
    );
    assert_eq!(
        std::fs::read_to_string(sandbox.store().join("oauth-token.json")).unwrap(),
        token
    );
    let mapping = std::fs::read_to_string(sandbox.store().join("profiles.json")).unwrap();
    let repeated = sandbox.run(&["--json", "status"]);
    assert!(repeated.status.success());
    assert_eq!(
        std::fs::read_to_string(sandbox.store().join("profiles.json")).unwrap(),
        mapping
    );
}

#[test]
fn a_present_empty_registry_prevents_legacy_migration() {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.store().join("profiles.json"),
        r#"{"defaultProfile":null,"profiles":[]}"#,
    )
    .unwrap();
    std::fs::write(
        sandbox.store().join("oauth-token.json"),
        r#"{"access_token":"legacy","expires_at":4102444800}"#,
    )
    .unwrap();

    let result = sandbox.run(&["--json", "status"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(body["profiles"].as_array().unwrap().len(), 0);
    assert!(sandbox.store().join("oauth-token.json").exists());
}

#[test]
fn failed_legacy_migration_keeps_the_legacy_entries_and_does_not_write_registry() {
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.store().join("client-credentials.json"), "not-json").unwrap();
    std::fs::write(
        sandbox.store().join("oauth-token.json"),
        r#"{"access_token":"legacy","expires_at":4102444800}"#,
    )
    .unwrap();

    let result = sandbox.run(&["status"]);
    assert!(!result.status.success());
    assert!(!sandbox.store().join("profiles.json").exists());
    assert_eq!(
        std::fs::read_to_string(sandbox.store().join("client-credentials.json")).unwrap(),
        "not-json"
    );
}

#[test]
fn status_can_select_one_profile_and_set_default_changes_implicit_selection() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();

    let filtered = sandbox.run(&["--json", "status", "--profile", "bob"]);
    assert!(
        filtered.status.success(),
        "{}",
        String::from_utf8_lossy(&filtered.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&filtered.stdout).unwrap();
    assert_eq!(body["profiles"].as_array().unwrap().len(), 1);
    assert_eq!(body["profiles"][0]["name"], "bob");
    assert_eq!(body["profiles"][0]["isDefault"], false);

    let changed = sandbox.run(&["profile", "set-default", "bob"]);
    assert!(
        changed.status.success(),
        "{}",
        String::from_utf8_lossy(&changed.stderr)
    );
    let status = sandbox.run(&["--json", "status"]);
    let body: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(body["defaultProfile"], "bob");
    assert_eq!(body["profiles"][0]["isDefault"], false);
    assert_eq!(body["profiles"][1]["isDefault"], true);

    let (url, request) = fake_bank_once(r#"{"accounts":[]}"#);
    let accounts = sandbox
        .command(&["accounts", "--json"])
        .env("SB1_TEST_API_BASE_URL", url)
        .output()
        .unwrap();
    assert!(accounts.status.success());
    assert!(request
        .join()
        .unwrap()
        .to_ascii_lowercase()
        .contains("authorization: bearer bob-token"));
}

#[test]
fn set_default_outputs_json_when_json_is_requested() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();

    let changed = sandbox.run(&["--json", "profile", "set-default", "bob"]);
    assert!(
        changed.status.success(),
        "{}",
        String::from_utf8_lossy(&changed.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_eq!(body, serde_json::json!({"defaultProfile": "bob"}));
}

#[test]
fn logout_requires_selection_with_multiple_profiles_and_only_clears_selected_profile() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();

    let ambiguous = sandbox.run(&["logout"]);
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("--profile"));

    let logout = sandbox.run(&["logout", "--profile", "alice", "--all"]);
    assert!(
        logout.status.success(),
        "{}",
        String::from_utf8_lossy(&logout.stderr)
    );
    let status = sandbox.run(&["--json", "status"]);
    let body: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(body["profiles"][0]["loggedIn"], false);
    assert_eq!(body["profiles"][0]["hasStoredCredentials"], false);
    assert_eq!(body["profiles"][1]["loggedIn"], true);
    assert_eq!(body["profiles"][1]["hasStoredCredentials"], true);
}

#[test]
fn refresh_uses_only_the_selected_profiles_credentials_and_token() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();
    let (url, request) = fake_bank_once(
        r#"{"access_token":"bob-refreshed","refresh_token":"bob-next","token_type":"Bearer","expires_in":3600}"#,
    );
    let result = sandbox
        .command(&["refresh", "--profile", "bob"])
        .env("SB1_TEST_API_BASE_URL", url)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let request = request.join().unwrap();
    assert!(request.starts_with("POST /oauth/token "));
    assert!(request.contains("bob-id"));
    assert!(request.contains("bob-secret"));
    assert!(request.contains("bob-refresh"));
    assert!(!request.contains("alice-secret"));
}

#[test]
fn hello_uses_the_selected_profiles_access_token() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();
    let (url, request) = fake_bank_once(r#"{"message":"hello bob"}"#);
    let result = sandbox
        .command(&["hello", "--profile", "bob"])
        .env("SB1_TEST_API_BASE_URL", url)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("hello bob"));
    let request = request.join().unwrap();
    assert!(request.starts_with("GET /common/helloworld "));
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer bob-token"));
}

#[test]
fn accounts_uses_the_selected_profiles_access_token() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();
    let (url, request) = fake_bank_once(
        r#"{"accounts":[{"key":"BOB-KEY","name":"Bob Account","accountNumber":"12345678903"}]}"#,
    );
    let result = sandbox
        .command(&["--json", "accounts", "--profile", "bob"])
        .env("SB1_TEST_API_BASE_URL", url)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(body["accounts"][0]["name"], "Bob Account");
    let request = request.join().unwrap();
    assert!(request.starts_with("GET /personal/banking/accounts "));
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer bob-token"));
}

#[test]
fn login_adds_a_profile_and_reauthentication_keeps_it_as_one_profile() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();

    let created = login_new_profile(&sandbox, "charlie", "charlie-id", "charlie-secret");
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let status = sandbox.run(&["--json", "status"]);
    let body: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(body["defaultProfile"], "alice");
    assert_eq!(body["profiles"].as_array().unwrap().len(), 3);
    assert_eq!(body["profiles"][2]["name"], "charlie");

    let reauthenticated =
        login_new_profile(&sandbox, "charlie", "charlie-new-id", "charlie-new-secret");
    assert!(
        reauthenticated.status.success(),
        "{}",
        String::from_utf8_lossy(&reauthenticated.stderr)
    );
    let status = sandbox.run(&["--json", "status"]);
    let body: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(body["profiles"].as_array().unwrap().len(), 3);
    assert_eq!(body["profiles"][2]["name"], "charlie");

    let (url, request) = fake_bank_once(
        r#"{"access_token":"charlie-refreshed","refresh_token":"charlie-next","expires_in":3600}"#,
    );
    let refreshed = sandbox
        .command(&["refresh", "--profile", "charlie"])
        .env("SB1_TEST_API_BASE_URL", url)
        .output()
        .unwrap();
    assert!(refreshed.status.success());
    let request = request.join().unwrap();
    assert!(request.contains("charlie-new-id"));
    assert!(request.contains("charlie-new-secret"));
    assert!(!request.contains("alice-secret"));
}

#[test]
fn login_preserves_a_default_changed_during_bankid_authentication() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();
    let pending = start_profile_login(
        &sandbox,
        "charlie",
        "charlie-id",
        "charlie-secret",
        r#"{"access_token":"charlie-access","refresh_token":"charlie-refresh","expires_in":3600}"#,
    );

    let changed = sandbox.run(&["profile", "set-default", "bob"]);
    assert!(changed.status.success());

    let (login, _) = finish_login(pending);
    assert!(
        login.status.success(),
        "{}",
        String::from_utf8_lossy(&login.stderr)
    );
    let status = sandbox.run(&["--json", "status"]);
    let body: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(body["defaultProfile"], "bob");
    assert_eq!(body["profiles"].as_array().unwrap().len(), 3);
}

#[test]
fn overlapping_profile_logins_do_not_overwrite_the_first_profiles_secrets() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();
    let first = start_profile_login(
        &sandbox,
        "charlie",
        "first-id",
        "first-secret",
        r#"{"access_token":"first-access","refresh_token":"first-refresh","expires_in":3600}"#,
    );
    let second = start_profile_login(
        &sandbox,
        "charlie",
        "second-id",
        "second-secret",
        r#"{"access_token":"second-access","refresh_token":"second-refresh","expires_in":3600}"#,
    );

    let (first, _) = finish_login(first);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let (second, _) = finish_login(second);
    assert!(!second.status.success());
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("profile 'charlie' already exists"),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let credentials: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            sandbox
                .store()
                .join("profile-636861726c6965-client-credentials.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(credentials["client_id"], "first-id");
    assert_eq!(credentials["client_secret"], "first-secret");
    let token: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            sandbox
                .store()
                .join("profile-636861726c6965-oauth-token.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(token["access_token"], "first-access");
    let status = sandbox.run(&["--json", "status"]);
    let body: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(body["profiles"].as_array().unwrap().len(), 3);
}

#[test]
fn first_successful_profile_becomes_default() {
    let sandbox = Sandbox::new();
    let login = login_new_profile(&sandbox, "partner", "partner-id", "partner-secret");
    assert!(
        login.status.success(),
        "{}",
        String::from_utf8_lossy(&login.stderr)
    );
    let status = sandbox.run(&["--json", "status"]);
    let body: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(body["defaultProfile"], "partner");
    assert_eq!(body["profiles"][0]["isDefault"], true);
}

#[test]
fn login_without_profile_reauthenticates_the_default_profile() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();
    let (login, request) = perform_login(&sandbox, vec!["login".to_owned()], None);
    assert!(
        login.status.success(),
        "{}",
        String::from_utf8_lossy(&login.stderr)
    );
    assert!(request.contains("alice-id"));
    assert!(request.contains("alice-secret"));
    assert!(!request.contains("bob-secret"));

    let status = sandbox.run(&["--json", "status"]);
    let body: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(body["defaultProfile"], "alice");
    assert_eq!(body["profiles"].as_array().unwrap().len(), 2);
}

#[test]
fn declining_new_profile_creation_does_not_write_a_profile() {
    let sandbox = Sandbox::new();
    let mut child = sandbox
        .command(&[
            "login",
            "--profile",
            "partner",
            "--client-id",
            "partner-id",
            "--client-secret",
            "partner-secret",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    let status = sandbox.run(&["--json", "status"]);
    let body: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(body["profiles"].as_array().unwrap().len(), 0);
}

#[test]
fn transfer_confirmation_and_account_resolution_use_the_selected_profile() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();
    let accounts = r#"{"accounts":[{"key":"BOB-CHECKING","name":"Checking","accountNumber":"11112222333"},{"key":"BOB-SAVINGS","name":"Savings","accountNumber":"44445555666"}]}"#;
    let replies: &'static [&'static str] =
        Box::leak(vec![accounts, accounts, r#"{"paymentId":"payment-1"}"#].into_boxed_slice());
    let (url, requests) = fake_bank_sequence(replies);
    let mut child = sandbox
        .command(&[
            "transfer",
            "debit",
            "--profile",
            "bob",
            "--from",
            "Checking",
            "--to",
            "Savings",
            "--amount",
            "250",
        ])
        .env("SB1_TEST_API_BASE_URL", url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains("profile: bob"));
    assert!(stdout.contains("Checking"));
    assert!(stdout.contains("Savings"));
    let requests = requests.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /personal/banking/accounts?"));
    assert!(requests[1].starts_with("GET /personal/banking/accounts?"));
    assert!(requests[2].starts_with("POST /personal/banking/transfer/debit "));
    assert!(requests.iter().all(|r| r
        .to_ascii_lowercase()
        .contains("authorization: bearer bob-token")));
    assert!(requests[2].contains("11112222333"));
    assert!(requests[2].contains("44445555666"));
}

#[test]
fn declining_transfer_confirmation_sends_no_money_movement_request() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();
    let accounts = r#"{"accounts":[{"key":"BOB-CHECKING","name":"Checking","accountNumber":"11112222333"},{"key":"BOB-SAVINGS","name":"Savings","accountNumber":"44445555666"}]}"#;
    let replies: &'static [&'static str] = Box::leak(vec![accounts, accounts].into_boxed_slice());
    let (url, requests) = fake_bank_sequence(replies);
    let mut child = sandbox
        .command(&[
            "transfer",
            "debit",
            "--profile",
            "bob",
            "--from",
            "Checking",
            "--to",
            "Savings",
            "--amount",
            "250",
        ])
        .env("SB1_TEST_API_BASE_URL", url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("Proceed? [y/N]"));
    assert!(String::from_utf8_lossy(&result.stdout).contains("Aborted."));
    let requests = requests.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|r| !r.starts_with("POST /personal/banking/transfer/")));
}

#[test]
fn transfer_requires_profile_when_multiple_profiles_are_configured() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();
    let result = sandbox.run(&[
        "transfer", "debit", "--from", "Checking", "--to", "Savings", "--amount", "250",
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("multiple profiles"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("--profile"));
}

#[test]
fn refresh_requires_a_profile_when_multiple_profiles_are_configured() {
    let sandbox = Sandbox::new();
    sandbox.configured_pair();
    let result = sandbox.run(&["refresh"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("multiple profiles"));
}
