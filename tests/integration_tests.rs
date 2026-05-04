use coreshift_core::inotify::decode_events;
use coreshift_core::spawn::{ExitStatus, SpawnBackend, SpawnOptions};

#[test]
fn test_spawn_echo_capture() {
    let output = SpawnOptions::builder(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "echo hello world".to_string(),
    ])
    .backend(SpawnBackend::PosixSpawn)
    .capture_stdout()
    .build()
    .unwrap()
    .run()
    .unwrap();

    assert_eq!(output.status, Some(ExitStatus::Exited(0)));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello world"
    );
}

#[test]
fn test_spawn_large_stdout() {
    // Generate ~100KB of output
    let script = "for i in $(seq 1 10000); do echo \"line $i\"; done";
    let output = SpawnOptions::builder(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        script.to_string(),
    ])
    .backend(SpawnBackend::PosixSpawn)
    .capture_stdout()
    .max_output(200_000)
    .build()
    .unwrap()
    .run()
    .unwrap();

    assert_eq!(output.status, Some(ExitStatus::Exited(0)));
    assert!(output.stdout.len() > 65536);
}

#[test]
fn test_inotify_decode_with_name() {
    let mut buf = Vec::new();
    let name = "test_file.txt";
    let name_bytes = name.as_bytes();
    let mut name_with_padding = name_bytes.to_vec();
    name_with_padding.push(0); // null terminator
    while !name_with_padding.len().is_multiple_of(8) {
        name_with_padding.push(0); // padding
    }
    let name_len = name_with_padding.len() as u32;

    // wd=1, mask=IN_MODIFY, cookie=0, len=name_len
    buf.extend_from_slice(&1i32.to_ne_bytes());
    buf.extend_from_slice(&libc::IN_MODIFY.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&name_len.to_ne_bytes());
    buf.extend_from_slice(&name_with_padding);

    let events = decode_events(&buf);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].wd, 1);
    assert_eq!(events[0].name, Some(name.as_bytes().to_vec()));
}

#[test]
fn test_exec_context_many_args() {
    let mut args = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "echo $@".to_string(),
        "--".to_string(),
    ];
    for i in 0..100 {
        args.push(format!("arg{}", i));
    }

    let output = SpawnOptions::builder(args)
        .backend(SpawnBackend::PosixSpawn)
        .capture_stdout()
        .build()
        .unwrap()
        .run()
        .unwrap();

    assert_eq!(output.status, Some(ExitStatus::Exited(0)));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("arg0"));
    assert!(stdout.contains("arg99"));
}
