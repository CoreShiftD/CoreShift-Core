use coreshift_core::inotify::{MODIFY_MASK, add_watch, read_events};
use coreshift_core::reactor::Reactor;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut reactor = Reactor::new()?;
    let inotify_fd = reactor.setup_inotify()?;

    let temp_dir = std::env::temp_dir();
    let temp_dir_str = temp_dir.to_string_lossy().into_owned();

    println!("Watching {} for modifications...", temp_dir_str);
    add_watch(&inotify_fd, &temp_dir_str, MODIFY_MASK)?;

    let mut events = Vec::new();
    // Monitor for 10 seconds
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        let n = reactor.wait(&mut events, 64, 1000)?;
        if n > 0 {
            for ev in &events {
                if Some(ev.token) == reactor.inotify_token {
                    let in_events = read_events(&inotify_fd)?;
                    for ie in in_events {
                        if let Some(name) = ie.name {
                            println!("File modified: {}", String::from_utf8_lossy(&name));
                        } else {
                            println!("Directory modified (wd={})", ie.wd);
                        }
                    }
                }
            }
        }
    }

    println!("Finished watching.");
    Ok(())
}
