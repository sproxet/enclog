extern crate sodiumoxide;

use std::error::Error;
use std::io;
use std::mem::transmute;
use std::iter::Iterator;

use sodiumoxide::crypto::{box_, hash, secretbox};
use sodiumoxide::init as sodiumoxide_init;
use sodiumoxide::randombytes::randombytes_into;

struct ZeroingVecU8(Vec<u8>);
impl Drop for ZeroingVecU8 {
    fn drop(&mut self) {
        for rm in self.0.iter_mut() {
            unsafe {
                (rm as *mut u8).write_volatile(0u8);
            }
        }
    }
}

pub struct LogWriter<'a, W: 'a + io::Write> {
    writer: &'a mut W,
    current_key: [u8; secretbox::KEYBYTES],
    iteration: u64,
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

        let first_symmetric_key = {
            let mut fsk = [0; secretbox::KEYBYTES];
            randombytes_into(&mut fsk);
            fsk
        };

        let version= 1;

        let version_and_first_symmetric_key = {
            let mut v_fsk = [0; secretbox::KEYBYTES + 8];
            {
                let (mut v, mut fsk) = v_fsk.split_at_mut(8);
                v.clone_from_slice(&unsafe { transmute::<u64, [u8; 8]>(version) });
                fsk.clone_from_slice(&first_symmetric_key);
            }
            v_fsk
        };

        let encrypted_header = box_::seal(&version_and_first_symmetric_key, &nonce,
                                          &reader_pubkey, &writer_seckey);


        writer.write_all(&writer_pubkey.0)?;
        writer.write_all(&encrypted_header)?;

        Ok(LogWriter {
            writer,
            iteration: 0,
            current_key: first_symmetric_key,
        })
    }

    pub fn log(&mut self, msg: &[u8]) -> Result<(), Box<Error>> {
        self.ratchet();

        let key = secretbox::Key(self.current_key.clone());

        // Each key is only used twice.
        let nonce_len = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let nonce_msg = secretbox::Nonce([1; secretbox::NONCEBYTES]);

        let iteration = unsafe { transmute::<u64, [u8; 8]>(self.iteration) };
        let i_msg = ZeroingVecU8({
            // We allocate the Vec with capacity to guarantee it won't be moved.
            let mut i_m = Vec::with_capacity(msg.len() + 8);
            i_m.extend_from_slice(&iteration);
            i_m.extend_from_slice(&msg);
            i_m
        });
        let enc_i_msg = ZeroingVecU8(secretbox::seal(&i_msg.0, &nonce_msg,&key));

        // Sign enc_msg.len(), putting the encrypted result in encrypted_length and discarding the
        // authentication tag. (There is no need for authentication of the length.)
        let msg_len_v = unsafe { transmute::<u64, [u8; 8]>(enc_i_msg.0.len() as u64) };
        let encrypted_length = ZeroingVecU8(
            secretbox::seal(&msg_len_v, &nonce_len, &key));

        self.writer.write_all(&encrypted_length.0)?;
        self.writer.write_all(&enc_i_msg.0)?;

        Ok(())
    }

    /// Up the iteration count and replace the key with the hash of the previous key.
    fn ratchet(&mut self) {
        // new_key is on the stack.
        let new_key = hash::hash(&self.current_key).0;
        self.current_key.copy_from_slice(&new_key[0..secretbox::KEYBYTES]);

        // We're not going to overflow a u64, and if we do, all it allows is reordering 2^64-record
        // chunks.
        self.iteration += 1;
    }
}

pub struct LogReader<'a, R: 'a + io::Read> {
    reader: &'a mut R,
    current_key: [u8; secretbox::KEYBYTES],
    iteration: u64,
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
            let mut pk = [0; box_::PUBLICKEYBYTES];
            reader.read_exact(&mut pk)?;
            box_::PublicKey(pk)
        };
        let nonce = box_::Nonce([0; box_::NONCEBYTES]);

        let mut encrypted_header = [0; secretbox::KEYBYTES + 8 + box_::MACBYTES];
        reader.read_exact(&mut encrypted_header)?;

        let header = box_::open(&encrypted_header, &nonce,
                                        &writer_pubkey, &reader_seckey).or(Err("invalid header"))?;
        assert_eq!(header.len(), secretbox::KEYBYTES + 8); // This should always be true.
        if &header[0..8] != unsafe { transmute::<u64, [u8; 8]>(1) } {
            Err("incompatible version")?;
        }
        let first_symmetric_key = {
            let mut fsk = [0; secretbox::KEYBYTES];
            fsk.copy_from_slice(&header[8..8+secretbox::KEYBYTES]);
            fsk
        };

        Ok(LogReader {
            reader,
            current_key: first_symmetric_key,
            iteration: 0,
        })
    }

    /// Up the iteration count and replace the key with the hash of the previous key.
    fn ratchet(&mut self) {
        // new_key is on the stack.
        let new_key = hash::hash(&self.current_key).0;
        self.current_key.copy_from_slice(&new_key[0..secretbox::KEYBYTES]);

        // We're not going to overflow a u64, and if we do, all it allows is reordering 2^64-record
        // chunks.
        self.iteration += 1;
    }
}
impl<'a, R: io::Read> Iterator for LogReader<'a, R> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        self.ratchet();

        let key = secretbox::Key(self.current_key.clone());

        // Each key is only used twice.
        let nonce_len = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let nonce_msg = secretbox::Nonce([1; secretbox::NONCEBYTES]);

        // read_exact() will return an Err if the file ends abruptly, and we will correspondingly
        // return None.

        let mut enc_len = [0u8; 8 + secretbox::MACBYTES];
        if let Err(_) = self.reader.read_exact(&mut enc_len) {
            return None;
        }

        let len_v = match secretbox::open(&enc_len, &nonce_len, &key) {
            Ok(v) => v,
            Err(_) => { return None; },
        };

        if len_v.len() < 8 {
            return None;
        }
        let mut len_a = [0; 8];
        len_a.copy_from_slice(&len_v[0..8]);
        let len: u64 = unsafe { transmute(len_a) };

        let mut encrypted = vec![0u8; len as usize];
        if let Err(_) = self.reader.read_exact(&mut encrypted) {
            return None;
        }

        let mut decrypted = match secretbox::open(&encrypted, &nonce_msg, &key) {
            Ok(v) => v,
            Err(_) => { return None; },
        };

        if decrypted.len() < 8 {
            return None;
        }
        let dec_msg = decrypted.split_off(8);
        let mut dec_iteration_a = [0u8; 8];
        dec_iteration_a.copy_from_slice(&decrypted[0..8]);

        let dec_i: u64 = unsafe { transmute(dec_iteration_a) };
        if dec_i != self.iteration {
            return None;
        }

        Some(dec_msg)
    }
}

#[cfg(test)]
mod tests {
    use sodiumoxide::crypto::box_;
    use super::{LogReader, LogWriter};
    use std::fs;
    use std::fs::File;

    #[test]
    fn write_read() {
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
    }
}
