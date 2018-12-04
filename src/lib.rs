extern crate sodiumoxide;

use std::error::Error;
use std::io;
use std::mem::transmute;
use std::iter::Iterator;

use sodiumoxide::crypto::{box_, hash, secretbox};
use sodiumoxide::init as sodiumoxide_init;
use sodiumoxide::randombytes::randombytes_into;

use std::u32; // u32::MAX
const BLOCK_SIZE: usize = 256;
const MSG_SIZE: usize = BLOCK_SIZE - secretbox::MACBYTES - 8; // (8 bytes for a u64 message number)
const HEADER_SIZE: usize = box_::PUBLICKEYBYTES + 1 /* version */ + secretbox::KEYBYTES + secretbox::MACBYTES;

pub struct LogWriter<'a, W: 'a + io::Write> {
    writer: &'a mut W,
    current_key: [u8; secretbox::KEYBYTES],
    msg_no: u64,
    poisoned: bool
}

impl<'a, W: io::Write> LogWriter<'a, W> {
    pub fn new(pubkey: &[u8], writer: &'a mut W) -> Result<LogWriter<'a, W>, Box<Error>> {
        if pubkey.len() != box_::PUBLICKEYBYTES {
            Err("invalid pubkey length")?;
        }

        // This needs to be called at least once in the program to make calls to randombytes_into()
        // thread-safe. It's fine to call it multiple times.
        sodiumoxide_init().or(Err("libsodium init failed"))?;

        let reader_pubkey = {
            let mut pk = [0; box_::PUBLICKEYBYTES];
            pk.copy_from_slice(&pubkey);
            box_::PublicKey(pk)
        };

        let (writer_pubkey, writer_seckey) = box_::gen_keypair();
        // The logger key will only ever be used for one operation.
        let nonce = box_::Nonce([0; box_::NONCEBYTES]);

        let mut first_symmetric_key= [0; secretbox::KEYBYTES];
        randombytes_into(&mut first_symmetric_key);

        // This should be incremented for every incompatible change.
        let version = 2;

        let mut v_fsk =  [0; secretbox::KEYBYTES + 1];
        v_fsk[0] = version;
        v_fsk[1..].clone_from_slice(&first_symmetric_key);

        let encrypted_header = box_::seal(&v_fsk, &nonce, &reader_pubkey, &writer_seckey);

        debug_assert_eq!(HEADER_SIZE, writer_pubkey.0.len() + encrypted_header.len());

        writer.write_all(&writer_pubkey.0)?;
        writer.write_all(&encrypted_header)?;

        Ok(LogWriter {
            writer,
            msg_no: 0,
            current_key: first_symmetric_key,
            poisoned: false,
        })
    }

    /// Log a message.
    pub fn log(&mut self, msg: &[u8]) -> Result<(), Box<Error>> {
        // msg_no must be incremented before successfully returning...

        if msg.len() > u32::MAX as usize {
            Err("msg too long")?;
        }
        let len: [u8; 4] = unsafe { transmute(msg.len() as u32) };

        let mut block = [0u8; MSG_SIZE];
        block[0..4].copy_from_slice(&len);

        if msg.len() <= MSG_SIZE - 4 {
            block[4..msg.len()+4].copy_from_slice(&msg);
            self.write_block(&block)?;
            self.msg_no += 1;
            return Ok(());
        } else {
            block[4..].copy_from_slice(&msg[..MSG_SIZE-4]);
            self.write_block(&block)?;
        }

        for block in msg[MSG_SIZE-4..].chunks(MSG_SIZE) {
            if block.len() == MSG_SIZE {
                self.write_block(&block)?;
            } else {
                let mut sparse_block = [0u8; MSG_SIZE];
                sparse_block[..block.len()].copy_from_slice(block);
                self.write_block(&sparse_block)?;
                // end loop
            }
        }

        self.msg_no += 1;
        Ok(())
    }

    /// Write one block of data, which must be exactly MSG_SIZE bytes. This only writes the block
    /// number and the authencrypted data. Caller is responsible for everything else.
    fn write_block(&mut self, msg: &[u8]) -> Result<(), Box<Error>> {
        assert_eq!(msg.len(), MSG_SIZE);

        if self.poisoned {
            Err("We are poisoned.")?;
        }

        let mut plaintext_block = [0u8; MSG_SIZE + 8];
        let msg_no: [u8; 8] = unsafe { transmute(self.msg_no) };
        plaintext_block[..8].copy_from_slice(&msg_no);
        plaintext_block[8..].copy_from_slice(msg);


        let key = secretbox::Key(self.current_key.clone());
        // Each key is only used once.
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let enc_block = secretbox::seal(&plaintext_block, &nonce, &key);

        self.writer.write_all(&enc_block).or_else(|e| {
            self.poisoned = true;
            Err(e)
        })?;

        self.ratchet();

        Ok(())
    }

    /// Replace the key with the hash of the previous key.
    fn ratchet(&mut self) {
        // new_key is on the stack.
        let new_key = hash::hash(&self.current_key).0;
        self.current_key.copy_from_slice(&new_key[0..secretbox::KEYBYTES]);
    }
}

pub struct LogReader<'a, R: 'a + io::Read> {
    reader: &'a mut R,
    current_key: [u8; secretbox::KEYBYTES],
}
impl<'a, R: io::Read> LogReader<'a, R> {
    pub fn new(seckey: &[u8], reader: &'a mut R) -> Result<LogReader<'a, R>, Box<Error>> {
        if seckey.len() != box_::SECRETKEYBYTES {
            Err("invalid seckey length")?;
        }

        let reader_seckey = {
            let mut rsk = [0; box_::SECRETKEYBYTES];
            rsk.copy_from_slice(seckey);
            box_::SecretKey(rsk)
        };

        let writer_pubkey = {
            let mut wpk = [0; box_::PUBLICKEYBYTES];
            reader.read_exact(&mut wpk)?;
            box_::PublicKey(wpk)
        };


        let mut encrypted_header = [0; secretbox::KEYBYTES + 1 + box_::MACBYTES];
        reader.read_exact(&mut encrypted_header)?;

        let nonce = box_::Nonce([0; box_::NONCEBYTES]);
        let header = box_::open(&encrypted_header, &nonce, &writer_pubkey,
                                &reader_seckey).or(Err("invalid header"))?;

        if header[0] != 2 {
            Err("incompatible version")?;
        }
        let mut first_symmetric_key = [0; secretbox::KEYBYTES];
        first_symmetric_key.copy_from_slice(&header[1..1+secretbox::KEYBYTES]);

        Ok(LogReader {
            reader,
            current_key: first_symmetric_key,
        })
    }

    /// Read one block from reader, returning (msg_no, msg).
    pub fn read_block(&mut self) -> Result<(u64, Vec<u8>), Box<Error>> {
        let mut ciphertext_block = [0u8; BLOCK_SIZE];
        self.reader.read_exact(&mut ciphertext_block)?;

        // Each key is used only once.
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let key = secretbox::Key(self.current_key.clone()) ;
        let mut msg = secretbox::open(&ciphertext_block, &nonce, &key)
            .or(Err("invalid block"))?;

        // Remove the message number from the rest of the message. You will notice that it is
        // assumed to be correct. This is possible because the key is ratcheted on every block, so
        // an attacker wouldn't be able to reorder them.
        let mut msg_no = [0u8; 8];
        msg_no.clone_from_slice(msg.drain(..8).collect::<Vec<u8>>().as_slice());
        let msg_no: u64 = unsafe{ transmute(msg_no) };

        self.ratchet();

        Ok((msg_no, msg))
    }

    /// Replace the key with the hash of the previous key.
    fn ratchet(&mut self) {
        // new_key is on the stack.
        let new_key = hash::hash(&self.current_key).0;
        self.current_key.copy_from_slice(&new_key[0..secretbox::KEYBYTES]);
    }
}
impl<'a, R: io::Read> Iterator for LogReader<'a, R> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        let initial_block = self.read_block().ok()?.1;

        let mut len = [0; 4];
        len.copy_from_slice(&initial_block[..4]);
        let len: u32 = unsafe { transmute(len) };
        let len = len as usize;

        let mut msg = vec![];

        if len <= MSG_SIZE - 4 {
            msg.extend_from_slice(&initial_block[4..4 + len]);
            return Some(msg);
        } else {
            msg.extend_from_slice(&initial_block[4..]);
        }

        let mut bytes_remaining = len + 4 - MSG_SIZE;
        while bytes_remaining >= MSG_SIZE {
            let block = self.read_block().ok()?.1;
            msg.extend_from_slice(&block);
            bytes_remaining -= MSG_SIZE;
        }
        if bytes_remaining > 0 {
            let block = self.read_block().ok()?.1;
            msg.extend_from_slice(&block[0..bytes_remaining]);
        }

        Some(msg)
    }
}

#[cfg(test)]
mod tests {
    use sodiumoxide::crypto::box_;
    use super::{LogReader, LogWriter};
    use std::io::{Cursor, Seek, SeekFrom};

    #[test]
    fn write_read() {
        let mut data = Cursor::new(vec![]);
        let (pubkey, seckey) = box_::gen_keypair();

        {
            let mut logger = LogWriter::new(&pubkey.0, &mut data).unwrap();
            logger.log(b"Hello, world!\n").unwrap();
            logger.log(b"Goodbye, world!\n").unwrap();
            logger.log(&[42; 420]).unwrap();
            logger.log(&[]).unwrap();
            logger.log(&[137; super::MSG_SIZE]).unwrap();
        }

        data.seek(SeekFrom::Start(0)).unwrap();

        {
            let mut reader = LogReader::new(&seckey.0, &mut data).unwrap();
            assert_eq!(reader.next().unwrap(), b"Hello, world!\n");
            assert_eq!(reader.next().unwrap(), b"Goodbye, world!\n");
            assert_eq!(reader.next().unwrap(), vec![42; 420]);
            assert_eq!(reader.next().unwrap(), &[]);
            assert_eq!(reader.next().unwrap(), vec![137; super::MSG_SIZE]);
            assert_eq!(reader.next(), None);
        }
    }
}
