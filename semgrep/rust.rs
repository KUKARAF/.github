async fn gate(req: Request, next: Next) {
    // ruleid: loopback-trusted-as-auth
    let l = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(addr)| addr.ip().is_loopback()).unwrap_or(false);
}
async fn h(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Response {
    // ruleid: loopback-trusted-as-auth
    if addr.ip().is_loopback() { ok() }
}
fn bind(a: SocketAddr) -> bool {
    // ok: loopback-trusted-as-auth
    a.ip().is_loopback()
}
fn admin_ok(presented: Option<&str>, expected: &String) -> bool {
    // ruleid: secret-compared-non-constant-time
    presented == Some(expected.as_str())
}
fn tok(t: &str, api_key: &str) -> bool {
    // ruleid: secret-compared-non-constant-time
    t == api_key
}
fn hashed(q: Q, row: R) -> bool {
    // ok: secret-compared-non-constant-time
    hash_key(&q.secret) != row.poll_secret_hash
}
fn lens(token: &str) -> bool {
    // ok: secret-compared-non-constant-time
    token.len() == 32
}
fn spawn(name: &str) {
    // ruleid: shell-command-spawn
    Command::new("bash").arg("-c").arg(name);
    // ok: shell-command-spawn
    Command::new("wget").arg(name);
}
async fn ws(ws: WebSocketUpgrade) -> Response {
    // ruleid: websocket-without-message-limit
    ws.on_upgrade(handle)
}
async fn ws2(ws: WebSocketUpgrade) -> Response {
    // ok: websocket-without-message-limit
    ws.max_message_size(1 << 20).on_upgrade(handle)
}
fn q(db: &Pool, name: &str) {
    // ruleid: sql-built-with-format
    sqlx::query(&format!("SELECT * FROM t WHERE n = '{name}'"));
}
fn page(x: &str) -> Html<String> {
    // ruleid: html-response-from-format
    Html(format!("<p>{x}</p>"))
}
fn version(current_version: u64, expected: &u64) -> bool {
    // ok: secret-compared-non-constant-time
    &current_version != expected
}
fn hmac(sig: &str, expected_sig: &str) -> bool {
    // ruleid: secret-compared-non-constant-time
    sig != expected_sig
}
