from py_ecc import bn128
import secrets
from web3 import Web3
from typing import Tuple
import hashlib


def validate_point(x: int, y: int) -> Tuple[bn128.FQ, bn128.FQ, bn128.FQ]:
    FQ = bn128.FQ

    if x >= bn128.field_modulus:
        raise Exception("Point x value is greater than field modulus")
    elif y >= bn128.field_modulus:
        raise Exception("Point y value is greater than field modulus")

    if (x, y) != (0, 0):
        p1 = (FQ(x), FQ(y), FQ(1))
        if not bn128.is_on_curve(p1, bn128.b):
            raise Exception("Point is not on the curve")
    else:
        p1 = (FQ(1), FQ(1), FQ(0))

    return p1

def get_random_generator() -> Tuple[bn128.FQ, bn128.FQ, bn128.FQ]:
    m = secrets.randbelow(bn128.field_modulus)
    p = bn128.G1
    res = bn128.multiply(p, m)
    return res

def generate_keypair():
    g1 = get_random_generator()
    g2 = get_random_generator()
    x1 = secrets.randbelow(bn128.field_modulus)
    x2 = secrets.randbelow(bn128.field_modulus)
    y1 = secrets.randbelow(bn128.field_modulus)
    y2 = secrets.randbelow(bn128.field_modulus)
    z = secrets.randbelow(bn128.field_modulus)

    private_key = {'x1':x1, 'x2':x2, 'y1':y1, 'y2':y2, 'z':z}

    public_key = {
        'g1':g1, 
        'g2':g2,
        'c': bn128.add(bn128.multiply(g1, x1), bn128.multiply(g2, x2)),
        'd': bn128.add(bn128.multiply(g1, y1), bn128.multiply(g2, y2)),
        'h': bn128.multiply(g1, z)
        }

    return private_key, public_key

def encrypt(public_key, message, pad, k=None):

    m = encode_x_to_ec_point(message, pad)
    k = secrets.randbelow(bn128.field_modulus) if k is None else k
    u1 = bn128.multiply(public_key['g1'], k)
    u2 = bn128.multiply(public_key['g2'], k)
    e = bn128.add(m, bn128.multiply(public_key['h'], k))
    a = Web3.solidityKeccak(['int256', 'int256', 'int256', 'int256', 'int256', 'int256'], [u1[0].n, u1[1].n, u2[0].n, u2[1].n, e[0].n, e[1].n])
    a = int.from_bytes(a, byteorder='big')
    v = bn128.add(bn128.multiply(public_key['c'], k), bn128.multiply(bn128.multiply(public_key['d'], k), a))

    return u1, u2, e, v, k

def decrypt(private_key, u1, u2, e, v):
    a = Web3.solidityKeccak(['int256', 'int256', 'int256', 'int256', 'int256', 'int256'], [u1[0].n, u1[1].n, u2[0].n, u2[1].n, e[0].n, e[1].n])
    a = int.from_bytes(a, byteorder='big')
    v_new = bn128.add(bn128.add(
        bn128.multiply(u1, private_key['x1']),
        bn128.multiply(u2, private_key['x2'])),
        bn128.multiply(bn128.add(
            bn128.multiply(u1, private_key['y1']),
            bn128.multiply(u2, private_key['y2'])), a))
    if v == v_new:
        return bn128.add(e, bn128.neg(bn128.multiply(u1, private_key['z'])))
    else:
        raise Exception("Invalid decryption")

def point_to_bytes(point):
    return '0x' + point[0].n.to_bytes(32, byteorder='big').hex() , "0x" + point[1].n.to_bytes(32, byteorder='big').hex()


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)

        Returns 1 if a has a square root modulo
        p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

def mod_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
        p should satisfy p % 4 == 3
    """
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    return pow(a, (p + 1) // 4, p)

def encode_x_to_ec_point(x, k):

    # check if byte length of x is smaller than 32 - k
    if len(x) > 32 - k:
        raise Exception("x is too long")
    
    increment = 2**(8*(32-k))
    x = int.from_bytes(x, byteorder='big')
    FQ = bn128.FQ

    for i in range(0, bn128.field_modulus - x, increment):
        ll = ((x + i) ** 3 + 3) % bn128.field_modulus
        y = mod_sqrt(ll, bn128.field_modulus)
        if y != 0:
            if bn128.is_on_curve((FQ(x + i), FQ(y)), bn128.b):
                return (FQ(x + i), FQ(y))
            

    raise Exception("No point found")

def decode_ec_point_to_x(point, k):
    return point[0].n.to_bytes(32, byteorder='big')[k:]

def f(b, x):
    if b == 0:
        x = b'\x00' * (32 - len(x)) + x
        return "0x" + bytes(Web3.solidityKeccak(['bytes32'], [x])).hex()
    else:
        # pad the message to 32 bytes
        x = b'\x00' * (32 - len(x)) + x
        return "0x" + hashlib.sha256(x).digest().hex()
