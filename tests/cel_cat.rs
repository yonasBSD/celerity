#![cfg(feature = "cli")]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn cel_cat_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_cel-cat") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_cel_cat") {
        return PathBuf::from(path);
    }

    let exe = std::env::current_exe().unwrap();
    let target_dir = exe.parent().unwrap().parent().unwrap();
    for candidate in ["cel-cat", "cel_cat"] {
        let path = target_dir.join(candidate);
        if path.exists() {
            return path;
        }
    }

    panic!("could not locate cel-cat binary");
}

#[test]
fn cel_cat_pub_sub_smoke() {
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = reserved.local_addr().unwrap().to_string();
    drop(reserved);

    let binary = cel_cat_path();
    let mut publisher = Command::new(&binary)
        .args(["pub", "--linger-ms", "1500", &endpoint, "hello"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_millis(150));

    let mut subscriber = Command::new(&binary)
        .args(["sub", &endpoint])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let stdout = subscriber.stdout.take().unwrap();
    let (line_tx, line_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| line);
        let _ = line_tx.send(result);
    });

    assert!(publisher.wait().unwrap().success());
    let line = line_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    assert_eq!(line.trim_end(), "hello");

    let _ = subscriber.kill();
    let _ = subscriber.wait();
}

#[test]
fn cel_cat_sub_can_start_before_pub() {
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = reserved.local_addr().unwrap().to_string();
    drop(reserved);

    let binary = cel_cat_path();
    let mut subscriber = Command::new(&binary)
        .args(["sub", &endpoint])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let stdout = subscriber.stdout.take().unwrap();
    let (line_tx, line_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| line);
        let _ = line_tx.send(result);
    });

    thread::sleep(Duration::from_millis(500));

    let mut publisher = Command::new(&binary)
        .args(["pub", "--linger-ms", "1500", &endpoint, "hello"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    assert!(publisher.wait().unwrap().success());
    let line = line_rx
        .recv_timeout(Duration::from_secs(4))
        .unwrap()
        .unwrap();
    assert_eq!(line.trim_end(), "hello");

    let _ = subscriber.kill();
    let _ = subscriber.wait();
}
