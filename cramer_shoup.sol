pragma solidity ^0.8.6;

struct PublicKey {
    bytes32[2] g1;
    bytes32[2] g2;
    bytes32[2] c;
    bytes32[2] d;
    bytes32[2] h;
}

struct ChiperText {
    bytes32[2] u1;
    bytes32[2] u2;
    bytes32[2] e;
    bytes32[2] v;
}

struct Commitment {
    bytes32 y;
    ChiperText ct0;
    ChiperText ct1;
}

contract CramerShoup {

    PublicKey pk;

    Commitment com;
    uint256 constant p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant p_minus_1_div_2 = 10944121435919637611123202872628637544348155578648911831344518947322613104291;
    uint256 constant p_plus_1_div_4 = 5472060717959818805561601436314318772174077789324455915672259473661306552146;


    event CommitmentVerified(uint8 b);

    function encrypt(
        bytes32[2] memory message,
        bytes32 k
    ) public returns (ChiperText memory) {
        ChiperText memory ct_mem;
        ct_mem.u1 = ecMul(pk.g1, k);
        ct_mem.u2 = ecMul(pk.g2, k);
        ct_mem.e = ecAdd(message, ecMul(pk.h, k)); 
        bytes32 a = keccak256(abi.encodePacked(ct_mem.u1[0], ct_mem.u1[1], ct_mem.u2[0], ct_mem.u2[1], ct_mem.e[0], ct_mem.e[1]));
        ct_mem.v = ecAdd(ecMul(pk.c, k), ecMul(ecMul(pk.d, k), a));
        return ct_mem;
    }

    function encryptAndCompare(
        bytes32[2] memory message,
        bytes32 k,
        uint8 b
    ) public returns (bool) {
        ChiperText storage ct = b == 0 ? com.ct0 : com.ct1;
        ChiperText memory ct_mem = encrypt(message, k);
        require((ct_mem.u1[0] == ct.u1[0]) && (ct_mem.u1[1] == ct.u1[1]), "u1 not matched");
        require((ct_mem.u2[0] == ct.u2[0]) && (ct_mem.u2[1] == ct.u2[1]), "u2 not matched");
        require((ct_mem.e[0] == ct.e[0]) && (ct_mem.e[1] == ct.e[1]), "e not matched");
        require((ct_mem.v[0] == ct.v[0]) && (ct_mem.v[1] == ct.v[1]), "v not matched");
        return true;
    }

    function reveal(
        uint8 b,
        bytes32 x,
        bytes32 k,
        uint256 pad
    ) public returns(bool) {
        require(com.y == f(b, x), "y not matched");
        bytes32[2] memory x_encoded = encode_x(x, pad);
        if (b == 0) {
            require(encryptAndCompare(x_encoded, k, b), "ct0 not matched");
        } else {
            require(encryptAndCompare(x_encoded, k, b), "ct1 not matched");
        }

        emit CommitmentVerified(b);
        return true;
    }

    function setPublicKey(PublicKey memory _pk) public {
        pk = _pk;
    }

    function commit(Commitment memory _com) public {
        com = _com;
    }

    function ecAdd(bytes32[2] memory a, bytes32[2] memory b) public returns (bytes32[2] memory result) {
        bytes32[4] memory input;
        input[0] = a[0];
        input[1] = a[1];
        input[2] = b[0];
        input[3] = b[1];
        assembly {
            let success := call(150, 0x06, 0, input, 0x80, result, 0x40)
            switch success
            case 0 {
                revert(0,0)
            }
        }
    }

    function ecMul(bytes32[2] memory g, bytes32 scalar) public returns (bytes32[2] memory result) {
        bytes32[3] memory input;
        input[0] = g[0];
        input[1] = g[1];
        input[2] = scalar;
        assembly {
            let success := call(6000, 0x07, 0, input, 0x60, result, 0x40)
            switch success
            case 0 {
                revert(0,0)
            }
        }
    }

    function expmod(uint256 base, uint256 e, uint256 m) public view returns (uint256 o) {

        assembly {
            // define pointer
            let po := mload(0x40)
            // store data assembly-favouring ways
            mstore(po, 0x20)             // Length of Base
            mstore(add(po, 0x20), 0x20)  // Length of Exponent
            mstore(add(po, 0x40), 0x20)  // Length of Modulus
            mstore(add(po, 0x60), base)  // Base
            mstore(add(po, 0x80), e)     // Exponent
            mstore(add(po, 0xa0), m)     // Modulus
            if iszero(staticcall(not(0), 0x05, po, 0xc0, po, 0x20)) {
                revert(0, 0)
            }
            // data
            o := mload(po)
        }}

    function f(uint8 b, bytes32 x) public pure returns (bytes32 result) {
        if (b == 0) {
            result = keccak256(abi.encodePacked(x));
        } else {
            result = sha256(abi.encodePacked(x));
        }
        return result;
    }
    
    function legendre_p(uint256 a) public view returns (bool) {
        uint256 lm = expmod(a, p_minus_1_div_2, p);
        if (lm == p - 1) {
            return false;
        } else {
            return true;
        }
    }

    function sqrt_p(uint256 a) public view returns (uint256) {
        if (legendre_p(a) && a != 0) {
            uint256 lm = expmod(a, p_plus_1_div_4, p);
            return lm;
        } else {
            return 0;
        }
    }

    function encode_x(bytes32 x, uint256 pad) public view returns (bytes32[2] memory){
        uint256 increment = 2**(8*(32-pad));
        uint256 x_int = uint256(x);

        for (uint256 i = 0; i < 2**pad; i++) {
            uint256 x_int_i = x_int + i*increment;
            uint256 y_int_i = sqrt_p(addmod(expmod(x_int_i, 3, p), 3, p));
            if (y_int_i != 0) {
                bytes32[2] memory result;
                result[0] = bytes32(x_int_i);
                result[1] = bytes32(y_int_i);
                return result;
            }
        }
        return [bytes32(0), bytes32(0)];
    }

}