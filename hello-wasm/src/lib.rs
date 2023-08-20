use std::fmt;

use aes::cipher::{generic_array::GenericArray, block_padding::Pkcs7, KeyIvInit, BlockDecryptMut};
use base64::{engine::general_purpose, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

// Define our error types. These may be customized for our error handling cases.
// Now we will be able to write our own errors, defer to an underlying error
// implementation, or do something in between.
#[derive(Debug, Clone)]
struct GenericError(String);

impl GenericError {
    pub fn new(s: &str) -> GenericError {
        GenericError(String::from(s))
    }
}

// Generation of an error is completely separate from how it is displayed.
// There's no need to be concerned about cluttering complex logic with the display style.
//
// Note that we don't store any extra info about the errors. This means we can't state
// which string failed to parse without modifying our types to carry that information.
impl fmt::Display for GenericError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for GenericError {  }

fn decrypt(pw: &str, salt: &str, kdf_iterations: u32, data: &str) -> Result<String, GenericError> {
    let kdf = pbkdf2_hmac_array::<Sha256, 32>(pw.as_bytes(), salt.as_bytes(), kdf_iterations);
    let hk = Hkdf::<Sha256>::from_prk(&kdf).map_err(|_| GenericError::new("Error creating Hkdf instance"))?; // ::new does both the extract and expand stages. This skips the extract stage.
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    hk.expand(b"enc", &mut enc_key).map_err(|_| GenericError::new("32 is a valid SHA256 output length"))?;
    hk.expand(b"mac", &mut mac_key).map_err(|_| GenericError::new("32 is a valid SHA256 output length"))?;
    let mut splits = data.split(".");
    let enc_type = splits.next().ok_or(GenericError::new("Malformatted JSON"))?;
    let mut splits = splits.next().ok_or(GenericError::new("Malformatted JSON"))?.split("|");
    let iv = general_purpose::STANDARD.decode(splits.next().ok_or(GenericError::new("Malformatted JSON"))?).map_err(|e| GenericError::new(&e.to_string()))?;
    let ciphertext = general_purpose::STANDARD.decode(splits.next().ok_or(GenericError::new("Malformatted JSON"))?).map_err(|e| GenericError::new(&e.to_string()))?;
    let expected_mac = general_purpose::STANDARD.decode(splits.next().ok_or(GenericError::new("Malformatted JSON"))?).map_err(|e| GenericError::new(&e.to_string()))?;
    if enc_type != "2" {
        return Err(GenericError::new("Only enc_type of 2 is supported"));
    }
    let mut mac = HmacSha256::new_from_slice(&mac_key).map_err(|_| GenericError::new("HMAC can take key of any size"))?;
    mac.update(&iv);
    mac.update(&ciphertext);
    let calculated_mac: [u8; 32] = mac.finalize().into_bytes().into();
    if expected_mac != calculated_mac {
        return Err(GenericError(String::from("MAC mismatch. Might be the wrong password!")));
    }
    let decrypted = Aes256CbcDec::new(&enc_key.into(), &GenericArray::from_exact_iter(iv.into_iter()).ok_or(GenericError::new("Failed to convert iv into a GenericArray!"))?)
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext).map_err(|e| GenericError::new(&e.to_string()))?;
    Ok(String::from_utf8(decrypted).map_err(|e| GenericError::new(&e.to_string()))?)
}

#[wasm_bindgen(getter_with_clone)]
pub struct DecryptResultJS {
    pub error: String,
    pub data: String,
}
#[wasm_bindgen]
pub fn decrypt_js(pw: &str, salt: &str, kdf_iterations: u32, data: &str) -> DecryptResultJS {
    match decrypt(pw, salt, kdf_iterations, data) {
        Ok(data) => {
            DecryptResultJS {
                error: String::new(),
                data
            }
        },
        Err(e) => {
            DecryptResultJS {
                error: e.to_string(),
                data: String::new()
            }
        }
    }
}

