extern crate bindgen;
extern crate cc;
extern crate git2;

use std::env;
use std::path::PathBuf;

use git2::Repository;

fn main() {
    let bearssl_root = find_bearssl_root();
    compile(&bearssl_root);
    gen_bindings(&bearssl_root);
}

fn find_bearssl_root() -> PathBuf {
    // Allow user override.
    match env::var_os("BEARSSL_DIR") {
        Some(p) => return PathBuf::from(p),
        None => {}
    }

    // If repo exists and we are debugging the build script, reuse the source repo.
    let bearssl_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bearssl");
    match env::var_os("BEARSSL_BUILD_DBG") {
        Some(_) => {
            let repo = Repository::discover(&bearssl_dir);
            if repo.is_ok() {
                println!("BEARSSL_BUILD_DBG set. Reusing source repo.");
                return bearssl_dir;
            }
        }
        None => {}
    }

    // Otherwise, do a checkout of the repo and we'll use that.
    let url = "https://www.bearssl.org/git/BearSSL";
    match Repository::clone(url, &bearssl_dir) {
        Ok(_) => return bearssl_dir,
        Err(e) => panic!("failed to clone BearSSL from {}: {}", url, e),
    };
}

fn compile(root: &PathBuf) {
    // https://github.com/alexcrichton/cc-rs/issues/253
    // Sigh... split into 3 libraries as a workaround on Windows...

    let settings = ["src/settings.c"];

    let aead = ["src/aead/ccm.c", "src/aead/eax.c", "src/aead/gcm.c"];

    let codec = [
        "src/codec/ccopy.c",
        "src/codec/dec16be.c",
        "src/codec/dec16le.c",
        "src/codec/dec32be.c",
        "src/codec/dec32le.c",
        "src/codec/dec64be.c",
        "src/codec/dec64le.c",
        "src/codec/enc16be.c",
        "src/codec/enc16le.c",
        "src/codec/enc32be.c",
        "src/codec/enc32le.c",
        "src/codec/enc64be.c",
        "src/codec/enc64le.c",
        "src/codec/pemdec.c",
        "src/codec/pemenc.c",
    ];

    let ec = [
        "src/ec/ec_all_m15.c",
        "src/ec/ec_all_m31.c",
        "src/ec/ec_c25519_i15.c",
        "src/ec/ec_c25519_i31.c",
        "src/ec/ec_c25519_m15.c",
        "src/ec/ec_c25519_m31.c",
        "src/ec/ec_c25519_m62.c",
        "src/ec/ec_c25519_m64.c",
        "src/ec/ec_curve25519.c",
        "src/ec/ec_default.c",
        "src/ec/ec_keygen.c",
        "src/ec/ec_p256_m15.c",
        "src/ec/ec_p256_m31.c",
        "src/ec/ec_p256_m62.c",
        "src/ec/ec_p256_m64.c",
        "src/ec/ec_prime_i15.c",
        "src/ec/ec_prime_i31.c",
        "src/ec/ec_pubkey.c",
        "src/ec/ec_secp256r1.c",
        "src/ec/ec_secp384r1.c",
        "src/ec/ec_secp521r1.c",
        "src/ec/ecdsa_atr.c",
        "src/ec/ecdsa_default_sign_asn1.c",
        "src/ec/ecdsa_default_sign_raw.c",
        "src/ec/ecdsa_default_vrfy_asn1.c",
        "src/ec/ecdsa_default_vrfy_raw.c",
        "src/ec/ecdsa_i15_bits.c",
        "src/ec/ecdsa_i15_sign_asn1.c",
        "src/ec/ecdsa_i15_sign_raw.c",
        "src/ec/ecdsa_i15_vrfy_asn1.c",
        "src/ec/ecdsa_i15_vrfy_raw.c",
        "src/ec/ecdsa_i31_bits.c",
        "src/ec/ecdsa_i31_sign_asn1.c",
        "src/ec/ecdsa_i31_sign_raw.c",
        "src/ec/ecdsa_i31_vrfy_asn1.c",
        "src/ec/ecdsa_i31_vrfy_raw.c",
        "src/ec/ecdsa_rta.c",
    ];

    let hash = [
        "src/hash/dig_oid.c",
        "src/hash/dig_size.c",
        "src/hash/ghash_ctmul.c",
        "src/hash/ghash_ctmul32.c",
        "src/hash/ghash_ctmul64.c",
        "src/hash/ghash_pclmul.c",
        "src/hash/ghash_pwr8.c",
        "src/hash/md5.c",
        "src/hash/md5sha1.c",
        "src/hash/mgf1.c",
        "src/hash/multihash.c",
        "src/hash/sha1.c",
        "src/hash/sha2big.c",
        "src/hash/sha2small.c",
    ];

    let int = [
        "src/int/i15_add.c",
        "src/int/i15_bitlen.c",
        "src/int/i15_decmod.c",
        "src/int/i15_decode.c",
        "src/int/i15_decred.c",
        "src/int/i15_encode.c",
        "src/int/i15_fmont.c",
        "src/int/i15_iszero.c",
        "src/int/i15_moddiv.c",
        "src/int/i15_modpow.c",
        "src/int/i15_modpow2.c",
        "src/int/i15_montmul.c",
        "src/int/i15_mulacc.c",
        "src/int/i15_muladd.c",
        "src/int/i15_ninv15.c",
        "src/int/i15_reduce.c",
        "src/int/i15_rshift.c",
        "src/int/i15_sub.c",
        "src/int/i15_tmont.c",
        "src/int/i31_add.c",
        "src/int/i31_bitlen.c",
        "src/int/i31_decmod.c",
        "src/int/i31_decode.c",
        "src/int/i31_decred.c",
        "src/int/i31_encode.c",
        "src/int/i31_fmont.c",
        "src/int/i31_iszero.c",
        "src/int/i31_moddiv.c",
        "src/int/i31_modpow.c",
        "src/int/i31_modpow2.c",
        "src/int/i31_montmul.c",
        "src/int/i31_mulacc.c",
        "src/int/i31_muladd.c",
        "src/int/i31_ninv31.c",
        "src/int/i31_reduce.c",
        "src/int/i31_rshift.c",
        "src/int/i31_sub.c",
        "src/int/i31_tmont.c",
        "src/int/i32_add.c",
        "src/int/i32_bitlen.c",
        "src/int/i32_decmod.c",
        "src/int/i32_decode.c",
        "src/int/i32_decred.c",
        "src/int/i32_div32.c",
        "src/int/i32_encode.c",
        "src/int/i32_fmont.c",
        "src/int/i32_iszero.c",
        "src/int/i32_modpow.c",
        "src/int/i32_montmul.c",
        "src/int/i32_mulacc.c",
        "src/int/i32_muladd.c",
        "src/int/i32_ninv32.c",
        "src/int/i32_reduce.c",
        "src/int/i32_sub.c",
        "src/int/i32_tmont.c",
        "src/int/i62_modpow2.c",
    ];

    let kdf = ["src/kdf/hkdf.c", "src/kdf/shake.c"];

    let mac = ["src/mac/hmac.c", "src/mac/hmac_ct.c"];

    let rand = [
        "src/rand/aesctr_drbg.c",
        "src/rand/hmac_drbg.c",
        "src/rand/sysrng.c",
    ];

    let rsa = [
        "src/rsa/rsa_default_keygen.c",
        "src/rsa/rsa_default_modulus.c",
        "src/rsa/rsa_default_oaep_decrypt.c",
        "src/rsa/rsa_default_oaep_encrypt.c",
        "src/rsa/rsa_default_pkcs1_sign.c",
        "src/rsa/rsa_default_pkcs1_vrfy.c",
        "src/rsa/rsa_default_priv.c",
        "src/rsa/rsa_default_privexp.c",
        "src/rsa/rsa_default_pss_sign.c",
        "src/rsa/rsa_default_pss_vrfy.c",
        "src/rsa/rsa_default_pub.c",
        "src/rsa/rsa_default_pubexp.c",
        "src/rsa/rsa_i15_keygen.c",
        "src/rsa/rsa_i15_modulus.c",
        "src/rsa/rsa_i15_oaep_decrypt.c",
        "src/rsa/rsa_i15_oaep_encrypt.c",
        "src/rsa/rsa_i15_pkcs1_sign.c",
        "src/rsa/rsa_i15_pkcs1_vrfy.c",
        "src/rsa/rsa_i15_priv.c",
        "src/rsa/rsa_i15_privexp.c",
        "src/rsa/rsa_i15_pss_sign.c",
        "src/rsa/rsa_i15_pss_vrfy.c",
        "src/rsa/rsa_i15_pub.c",
        "src/rsa/rsa_i15_pubexp.c",
        "src/rsa/rsa_i31_keygen.c",
        "src/rsa/rsa_i31_keygen_inner.c",
        "src/rsa/rsa_i31_modulus.c",
        "src/rsa/rsa_i31_oaep_decrypt.c",
        "src/rsa/rsa_i31_oaep_encrypt.c",
        "src/rsa/rsa_i31_pkcs1_sign.c",
        "src/rsa/rsa_i31_pkcs1_vrfy.c",
        "src/rsa/rsa_i31_priv.c",
        "src/rsa/rsa_i31_privexp.c",
        "src/rsa/rsa_i31_pss_sign.c",
        "src/rsa/rsa_i31_pss_vrfy.c",
        "src/rsa/rsa_i31_pub.c",
        "src/rsa/rsa_i31_pubexp.c",
        "src/rsa/rsa_i32_oaep_decrypt.c",
        "src/rsa/rsa_i32_oaep_encrypt.c",
        "src/rsa/rsa_i32_pkcs1_sign.c",
        "src/rsa/rsa_i32_pkcs1_vrfy.c",
        "src/rsa/rsa_i32_priv.c",
        "src/rsa/rsa_i32_pss_sign.c",
        "src/rsa/rsa_i32_pss_vrfy.c",
        "src/rsa/rsa_i32_pub.c",
        "src/rsa/rsa_i62_keygen.c",
        "src/rsa/rsa_i62_oaep_decrypt.c",
        "src/rsa/rsa_i62_oaep_encrypt.c",
        "src/rsa/rsa_i62_pkcs1_sign.c",
        "src/rsa/rsa_i62_pkcs1_vrfy.c",
        "src/rsa/rsa_i62_priv.c",
        "src/rsa/rsa_i62_pss_sign.c",
        "src/rsa/rsa_i62_pss_vrfy.c",
        "src/rsa/rsa_i62_pub.c",
        "src/rsa/rsa_oaep_pad.c",
        "src/rsa/rsa_oaep_unpad.c",
        "src/rsa/rsa_pkcs1_sig_pad.c",
        "src/rsa/rsa_pkcs1_sig_unpad.c",
        "src/rsa/rsa_pss_sig_pad.c",
        "src/rsa/rsa_pss_sig_unpad.c",
        "src/rsa/rsa_ssl_decrypt.c",
    ];

    let ssl = [
        "src/ssl/prf.c",
        "src/ssl/prf_md5sha1.c",
        "src/ssl/prf_sha256.c",
        "src/ssl/prf_sha384.c",
        "src/ssl/ssl_ccert_single_ec.c",
        "src/ssl/ssl_ccert_single_rsa.c",
        "src/ssl/ssl_client.c",
        "src/ssl/ssl_client_default_rsapub.c",
        "src/ssl/ssl_client_full.c",
        "src/ssl/ssl_engine.c",
        "src/ssl/ssl_engine_default_aescbc.c",
        "src/ssl/ssl_engine_default_aesccm.c",
        "src/ssl/ssl_engine_default_aesgcm.c",
        "src/ssl/ssl_engine_default_chapol.c",
        "src/ssl/ssl_engine_default_descbc.c",
        "src/ssl/ssl_engine_default_ec.c",
        "src/ssl/ssl_engine_default_ecdsa.c",
        "src/ssl/ssl_engine_default_rsavrfy.c",
        "src/ssl/ssl_hashes.c",
        "src/ssl/ssl_hs_client.c",
        "src/ssl/ssl_hs_server.c",
        "src/ssl/ssl_io.c",
        "src/ssl/ssl_keyexport.c",
        "src/ssl/ssl_lru.c",
        "src/ssl/ssl_rec_cbc.c",
        "src/ssl/ssl_rec_ccm.c",
        "src/ssl/ssl_rec_chapol.c",
        "src/ssl/ssl_rec_gcm.c",
        "src/ssl/ssl_scert_single_ec.c",
        "src/ssl/ssl_scert_single_rsa.c",
        "src/ssl/ssl_server.c",
        "src/ssl/ssl_server_full_ec.c",
        "src/ssl/ssl_server_full_rsa.c",
        "src/ssl/ssl_server_mine2c.c",
        "src/ssl/ssl_server_mine2g.c",
        "src/ssl/ssl_server_minf2c.c",
        "src/ssl/ssl_server_minf2g.c",
        "src/ssl/ssl_server_minr2g.c",
        "src/ssl/ssl_server_minu2g.c",
        "src/ssl/ssl_server_minv2g.c",
    ];

    let symcipher = [
        "src/symcipher/aes_big_cbcdec.c",
        "src/symcipher/aes_big_cbcenc.c",
        "src/symcipher/aes_big_ctr.c",
        "src/symcipher/aes_big_ctrcbc.c",
        "src/symcipher/aes_big_dec.c",
        "src/symcipher/aes_big_enc.c",
        "src/symcipher/aes_common.c",
        "src/symcipher/aes_ct.c",
        "src/symcipher/aes_ct64.c",
        "src/symcipher/aes_ct64_cbcdec.c",
        "src/symcipher/aes_ct64_cbcenc.c",
        "src/symcipher/aes_ct64_ctr.c",
        "src/symcipher/aes_ct64_ctrcbc.c",
        "src/symcipher/aes_ct64_dec.c",
        "src/symcipher/aes_ct64_enc.c",
        "src/symcipher/aes_ct_cbcdec.c",
        "src/symcipher/aes_ct_cbcenc.c",
        "src/symcipher/aes_ct_ctr.c",
        "src/symcipher/aes_ct_ctrcbc.c",
        "src/symcipher/aes_ct_dec.c",
        "src/symcipher/aes_ct_enc.c",
        "src/symcipher/aes_pwr8.c",
        "src/symcipher/aes_pwr8_cbcdec.c",
        "src/symcipher/aes_pwr8_cbcenc.c",
        "src/symcipher/aes_pwr8_ctr.c",
        "src/symcipher/aes_pwr8_ctrcbc.c",
        "src/symcipher/aes_small_cbcdec.c",
        "src/symcipher/aes_small_cbcenc.c",
        "src/symcipher/aes_small_ctr.c",
        "src/symcipher/aes_small_ctrcbc.c",
        "src/symcipher/aes_small_dec.c",
        "src/symcipher/aes_small_enc.c",
        "src/symcipher/aes_x86ni.c",
        "src/symcipher/aes_x86ni_cbcdec.c",
        "src/symcipher/aes_x86ni_cbcenc.c",
        "src/symcipher/aes_x86ni_ctr.c",
        "src/symcipher/aes_x86ni_ctrcbc.c",
        "src/symcipher/chacha20_ct.c",
        "src/symcipher/chacha20_sse2.c",
        "src/symcipher/des_ct.c",
        "src/symcipher/des_ct_cbcdec.c",
        "src/symcipher/des_ct_cbcenc.c",
        "src/symcipher/des_support.c",
        "src/symcipher/des_tab.c",
        "src/symcipher/des_tab_cbcdec.c",
        "src/symcipher/des_tab_cbcenc.c",
        "src/symcipher/poly1305_ctmul.c",
        "src/symcipher/poly1305_ctmul32.c",
        "src/symcipher/poly1305_ctmulq.c",
        "src/symcipher/poly1305_i15.c",
    ];

    let x509 = [
        "src/x509/asn1enc.c",
        "src/x509/encode_ec_pk8der.c",
        "src/x509/encode_ec_rawder.c",
        "src/x509/encode_rsa_pk8der.c",
        "src/x509/encode_rsa_rawder.c",
        "src/x509/skey_decoder.c",
        "src/x509/x509_decoder.c",
        "src/x509/x509_knownkey.c",
        "src/x509/x509_minimal.c",
        "src/x509/x509_minimal_full.c",
    ];

    let all_src : [&[&'static str]; 13] = [
        &settings, &aead, &codec, &ec, &hash, &int, &kdf, &mac,
        &rand, &rsa, &ssl, &symcipher, &x509,
    ];

    for list in all_src.iter() {
        // Was trying to be cute. Didn't work...
        // let src_files : [&'static str] = (*(*list).iter()).collect();

        let mut src_files_with_paths = Vec::new();
        // Extract a library name from the source directory structure.
        let first_src = PathBuf::from(list[0]);
        let lib_name = PathBuf::from(first_src.components().nth(1).unwrap().as_os_str());
        let lib_name_stem = lib_name.file_stem().unwrap();

        for src_file in list.iter() {
            src_files_with_paths.push(root.join(src_file));
        }

        let mut lib_name = String::from("bearssl-");
        lib_name.push_str(lib_name_stem.to_str().unwrap());

        cc::Build::new()
            .files(src_files_with_paths)
            .include(root.join("inc"))
            .include(root.join("src"))
            .compile(&lib_name)
    }
}

fn gen_bindings(root: &PathBuf) {
    let header = root.join("inc/bearssl.h");

    println!("cargo:rerun-if-changed={}", header.to_str().unwrap());

    // HINT: https://github.com/rust-lang/rust-bindgen/issues/1229
    // export BINDGEN_EXTRA_CLANG_ARGS="--sysroot /path/to/sysroot -I/other/header/dir"
    // Use absolute paths- no MSYS2 shortcuts like "/opt"; use "C:/msys64/opt/".
    let bindings = bindgen::Builder::default()
        .header(header.to_str().unwrap())
        .ctypes_prefix("cty")
        .use_core()
        .clang_arg("-target") // Not sure if required- bindings "work" without this or sysroot
                              // or some other combo of command-line options I forget.
        .clang_arg(env::var("TARGET").unwrap())
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
}
