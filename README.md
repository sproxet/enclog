enclog
======

enclog is a Rust crate that provides imperfect forward secrecy for logging (an attacker can compromise future messages,
but not past ones) for logging. After a message is logged, the logger will no longer be able to view it. This is could
e.g. allow you to log secrets without fear that an attacker who compromises your server will get access to already
logged data.

This crate is currently pre-alpha. Do not use it in production.

Usage
-----

```rust
use sodiumoxide::crypto::box_;
use enclog:{LogReader, LogWriter};
use std::fs;
use std::fs::File;

let mut data = File::create("/tmp/enclog.test").unwrap();
let (pubkey, seckey) = box_::gen_keypair();

{
    let mut logger = LogWriter::new(&pubkey.0, &mut data).unwrap();
    logger.log(b"Hello, world!\n").unwrap();
    logger.log(b"Goodbye, world!\n").unwrap();
}

let mut data = File::open("/tmp/enclog.test").unwrap();

{
    let mut reader = LogReader::new(&seckey.0, &mut data).unwrap();
    assert_eq!(reader.next().unwrap(), b"Hello, world!\n");
    assert_eq!(reader.next().unwrap(), b"Goodbye, world!\n");
    assert_eq!(reader.next(), None);
}

fs::remove_file("/tmp/enclog.test").unwrap();
```