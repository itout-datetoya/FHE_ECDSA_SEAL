from seal import *
import numpy as np

from random import randint

def u256_to_array(number, array_size, length = 4):
    num_string = format(number, 'x')
    num_string = '0' * (array_size*length-len(num_string)) + num_string
    num_array = []
    i = array_size * length
    while i-length >= 0:
        num_array.append(int(num_string[i-length:i], 16))
        i -= length
    return num_array

def array_to_u256(array_u16, base=16, length=4):
    number = int(0)
    for i in range(len(array_u16)):
        num_string = format(array_u16[i], 'x')
        num_string = '0' + num_string
        number += int(num_string, 16) * base**(length*i)
    return int(number)

def plain_row_to_enc_col(encryptor, encoder, plain_row, slot_count):
    encrypted_col = []
    for i in range(slot_count):
        if plain_row[i] != 0:
            encrypted_col.append(encryptor.encrypt(encoder.encode([plain_row[i]])))
    return encrypted_col

def enc_col_to_plain_row(decryptor, encoder, encrypted_col):
    plain_row = []
    for i in range(len(encrypted_col)):
        plain_row.append(encoder.decode(decryptor.decrypt(encrypted_col[i]))[0])
    return plain_row


def u256_add(evaluator, encrypted_a_col, encrypted_b_col):
    a_length = len(encrypted_a_col)
    b_length = len(encrypted_b_col)
    encrpyted_result = []
    if a_length == max(a_length, b_length):
        for i in range(b_length):
            encrpyted_result.append(evaluator.add(encrypted_a_col[i], encrypted_b_col[i]))
        for i in range(a_length - b_length):
            encrpyted_result.append(encrypted_a_col[i + b_length])
    else:
        for i in range(a_length):
            encrpyted_result.append(evaluator.add(encrypted_a_col[i], encrypted_b_col[i]))
        for i in range(b_length - a_length):
            encrpyted_result.append(encrypted_b_col[i + a_length])

    return encrpyted_result

def u256_add_plain(encryptor, evaluator, encoder, encrypted_col, plain_row):
    enc_length = len(encrypted_col)
    pl_length = len(plain_row)
    encrpyted_result = []
    if enc_length == max(enc_length, pl_length):
        for i in range(pl_length):
            plain_element = [plain_row[i]]
            encrpyted_result.append(evaluator.add_plain(encrypted_col[i], encoder.encode(plain_element)))
        for i in range(enc_length - pl_length):
            encrpyted_result.append(encrypted_col[i + pl_length])
    else:
        for i in range(enc_length):
            plain_element = [plain_row[i]]
            encrpyted_result.append(evaluator.add_plain(encrypted_col[i], encoder.encode(plain_element)))
        for i in range(pl_length - enc_length):
            plain_element = [plain_row[i + enc_length]]
            encrpyted_result.append(encryptor.encrypt(encoder.encode(plain_element)))
    
    return encrpyted_result

def u256_multiply(evaluator, encrypted_a_col, encrypted_b_col):
    encrpyted_result = []
    for i in range(len(encrypted_b_col)):
        part_prods = []
        for j in range(len(encrypted_a_col)):
            part_prods.append(evaluator.multiply(encrypted_a_col[j], encrypted_b_col[i]))
            if i == 0 or j == len(encrypted_a_col)-1:
                encrpyted_result.append(part_prods[j])
            else:
                encrpyted_result[i+j] = evaluator.add(encrpyted_result[i+j], part_prods[j])

    return encrpyted_result

def u256_multiply_plain(evaluator, encoder, encrypted_col, plain_row):
    encrpyted_result = []
    for i in range(len(plain_row)):
        if plain_row[i] != 0:
            plain_element = [plain_row[i]]
            part_prods = []
            for j in range(len(encrypted_col)):
                part_prods.append(evaluator.multiply_plain(encrypted_col[j], encoder.encode(plain_element)))
                if i == 0 or j == len(encrypted_col)-1:
                    encrpyted_result.append(part_prods[j])
                else:
                    encrpyted_result[i+j] = evaluator.add(encrpyted_result[i+j], part_prods[j])

    return encrpyted_result


def test():

    parms = EncryptionParameters(scheme_type.bgv)
    poly_modulus_degree = 8192
    #poly_modulus_degree = 16384
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 60))
    context = SEALContext(parms)

    keygen = KeyGenerator(context)
    secret_key = keygen.secret_key()
    public_key = keygen.create_public_key()
    relin_keys = keygen.create_relin_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)
    batch_encoder = BatchEncoder(context)
    slot_count = 128

    u256_a = randint(0, 2**256)
    u256_b = randint(0, 2**256)

    array_u16_a = u256_to_array(u256_a, slot_count)
    array_u16_b = u256_to_array(u256_b, slot_count)

    encrypted_a = plain_row_to_enc_col(encryptor, batch_encoder, array_u16_a, slot_count)
    encrypted_b = plain_row_to_enc_col(encryptor, batch_encoder, array_u16_b, slot_count)

    encrypted_sum_ee = u256_add(evaluator, encrypted_a, encrypted_b)
    encrypted_sum_ep = u256_add_plain(encryptor, evaluator, batch_encoder, encrypted_a, array_u16_b)
    encrypted_prod_ee = u256_multiply(evaluator, encrypted_a, encrypted_b)
    encrypted_prod_ep = u256_multiply_plain(evaluator, batch_encoder, encrypted_a, array_u16_b)

    array_sum_ee = enc_col_to_plain_row(decryptor, batch_encoder, encrypted_sum_ee)
    array_sum_ep = enc_col_to_plain_row(decryptor, batch_encoder, encrypted_sum_ep)
    array_prod_ee = enc_col_to_plain_row(decryptor, batch_encoder, encrypted_prod_ee)
    array_prod_ep = enc_col_to_plain_row(decryptor, batch_encoder, encrypted_prod_ep)

    sum_ee = array_to_u256(array_sum_ee)
    sum_ep = array_to_u256(array_sum_ep)
    prod_ee = array_to_u256(array_prod_ee)
    prod_ep = array_to_u256(array_prod_ep)

    sum = u256_a + u256_b
    prod = u256_a * u256_b

    if sum_ee == sum:
        print("u256_add():OK")
    else:
        print("u256_add():FAIL")

    if sum_ep == sum:
        print("u256_add_plain():OK")
    else:
        print("u256_add_plain():FAIL")

    if prod_ee == prod:
        print("u256_multiply():OK")
    else:
        print("u256_multiply():FAIL")

    if prod_ep == prod:
        print("u256_multiply_plain():OK")
    else:
        print("u256_multiply_plain():FAIL")
    
    print("")


if __name__ == "__main__":
    for i in range(5):
        test()