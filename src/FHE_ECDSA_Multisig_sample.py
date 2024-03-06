from seal import *
import numpy as np
from seal_uint256 import (
    u256_to_array,
    array_to_u256,
    plain_row_to_enc_col,
    enc_col_to_plain_row,
    u256_add,
    u256_add_plain,
    u256_multiply,
    u256_multiply_plain,
)

from random import randint
from ecc import S256Point, Signature, PrivateKey

A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


parms = EncryptionParameters(scheme_type.bgv)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 60))
context = SEALContext(parms)


sk_a = PrivateKey(randint(0, N))
pk_a = sk_a.point

sk_b = PrivateKey(randint(0, N))
pk_b = sk_b.point

pk = pk_a + pk_b # No need for Alice and Bob to cooperate for compute the public key.
z = randint(0, 2**256)


# Alice
k_a = sk_a.deterministic_k(z)
k_a_inv = pow(k_a, N-2, N)


# Bob
k_b = sk_b.deterministic_k(z)
k_b_inv = pow(k_b, N-2, N)


# Alice
keygen = KeyGenerator(context)
secret_key = keygen.secret_key()
public_key = keygen.create_public_key() # send to Bob
relin_keys = keygen.create_relin_keys()

encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)
batch_encoder = BatchEncoder(context)
slot_count = 128

R_a = k_a * G # send to Bob
secret_a_array = u256_to_array(sk_a.secret, slot_count)
encrypted_secret_a = plain_row_to_enc_col(encryptor, batch_encoder, secret_a_array, slot_count) # send to Bob


# Bob
R = k_b * R_a
r = R.x.num # send to Alice
plain_s_former_array = u256_to_array(((z + r * sk_b.secret) * k_b_inv) % N, slot_count)
plain_rk_array = u256_to_array((r * k_b_inv) % N, slot_count)
encrypted_s_latter = u256_multiply_plain(encryptor, evaluator, batch_encoder, encrypted_secret_a, plain_rk_array)
encrypted_s_prime = u256_add_plain(encryptor, evaluator, batch_encoder, encrypted_s_latter, plain_s_former_array) # send to Alice


# Alice
s_prime_array = enc_col_to_plain_row(decryptor, batch_encoder, encrypted_s_prime)
s = array_to_u256(s_prime_array) * k_a_inv % N
if s > N / 2:
    s = N - s
sig = Signature(r, s)



if pk.verify(z, sig):
    print("Verify")
else:
    print("Fail")






