use coreshift_core::fs::readahead;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Instant;

struct RawFdRef(RawFd);

impl AsRawFd for RawFdRef {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "usage: readahead_bench <path>"))?;

    let mut file = File::open(&path)?;
    let len = file.metadata()?.len().min(8 * 1024 * 1024) as usize;

    let start = Instant::now();
    readahead(RawFdRef(file.as_raw_fd()), 0, len)?;
    let readahead_elapsed = start.elapsed();

    let mut buf = vec![0u8; len];
    let start = Instant::now();
    let read_len = file.read(&mut buf)?;
    let read_elapsed = start.elapsed();

    println!("readahead({} bytes): {:?}", len, readahead_elapsed);
    println!("read({} bytes): {:?}", read_len, read_elapsed);

    Ok(())
}
