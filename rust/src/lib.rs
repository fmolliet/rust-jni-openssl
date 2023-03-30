mod utils;
use jni::objects::{JClass, JObject, JString, JValue};
use jni::JNIEnv;
use openssl::bn::BigNum;
use openssl::dh::Dh;
use openssl::pkey::Private;
use utils::{encode_hex, vec_to_array};

struct Keys<'a> {
    private_key: JString<'a>,
    public_key: JString<'a>,
}

#[no_mangle]
pub extern "system" fn Java_io_winty_sec_Keyexchange_generateKeys(
    mut env: JNIEnv,
    _class: JClass,
    callback: JObject,
) {
    let keypair = generate_key_pair();

    let keys = Keys {
        private_key: env.new_string(keypair.private_key().to_string()).unwrap(),
        public_key: env.new_string(keypair.public_key().to_string()).unwrap(),
    };

    let callback_signature = "(Ljava/lang/String;Ljava/lang/String;)V";

    let args = &[
        JValue::from(&keys.private_key),
        JValue::from(&keys.public_key),
    ];

    env.call_method(callback, "onKeysGenerated", callback_signature, args)
        .unwrap();
}

#[no_mangle]
pub extern "system" fn Java_io_winty_sec_Keyexchange_exchangeKeys(
    mut env: JNIEnv,
    _class: JClass,
    callback: JObject,
    private_key: JString,
    public_key: JString,
) {
    // Crio uma instancia de 1024 bits
    let dh = Dh::get_1024_160().unwrap();
    // Coloco a chave gerada anteriormente
    let keypair = dh
        .set_private_key(convert_jstring_to_bignum( &mut env, private_key))
        .unwrap();
    // Computa o segredo com a chave publica
    let secret = keypair
        .compute_key(convert_jstring_to_bignum(&mut env, public_key).as_ref())
        .unwrap();
    // Assinatura do metodo
    let callback_signature = "(Ljava/lang/String;)V";
    
    let binding = JString::from(
        env.new_string(encode_hex(&vec_to_array::<u8, 128>(secret))).unwrap(),
    );
    
    let args = &[JValue::from(&binding)];

    env.call_method(callback, "onKeyExchange", callback_signature, args)
        .unwrap();
}

pub fn generate_key_pair() -> Dh<Private> {
    // Gerando as chaves privadas e públicas
    let dh = Dh::get_1024_160().unwrap();

    dh.generate_key().unwrap()
}

fn convert_jstring_to_bignum( env: &mut JNIEnv, j_str: JString) -> BigNum {
    let java_str: String  = env.get_string(&j_str).unwrap().into();

    BigNum::from_dec_str(&java_str.to_string()).unwrap()
}
