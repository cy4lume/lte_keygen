# [usim]
# mode = soft
# algo = milenage
# opc  = 63BFA50EE6523365FF14C1F45F88737D
# k    = 00112233445566778899aabbccddeeff
# imsi = 001010123456780
# imei = 353490069873319

# imsi = 1010000023448
# k = ca7c55125829396d335bd8dbcdcde151
# opc = d93b00efeaf0bb4e77c060e641497b4d
# amf = \x90\x01
# sqn = 401
# qci = 7


import hmac, hashlib
from dataclasses import dataclass
from enum import IntEnum, unique
from Crypto.Cipher import AES

@unique
class FC(IntEnum):
    K_ASME     = 0x10 # FC_EPS_K_ASME_DERIVATION
    K_ENB      = 0x11 # FC_EPS_K_ENB_DERIVATION
    NH         = 0x12 # FC_EPS_NH_DERIVATION
    K_ENB_STAR = 0x13 # FC_EPS_K_ENB_STAR_DERIVATION
    ALGO_KEY   = 0x15 # FC_EPS_ALGORITHM_KEY_DERIVATION

@unique
class AlgoType(IntEnum):
    NAS_ENC = 0x01 # ALGO_EPS_DISTINGUISHER_NAS_ENC_ALG
    NAS_INT = 0x02 # ALGO_EPS_DISTINGUISHER_NAS_INT_ALG
    RRC_ENC = 0x03 # ALGO_EPS_DISTINGUISHER_RRC_ENC_ALG
    RRC_INT = 0x04 # ALGO_EPS_DISTINGUISHER_RRC_INT_ALG
    UP_ENC  = 0x05 # ALGO_EPS_DISTINGUISHER_UP_ENC_ALG
    UP_INT  = 0x06 # ALGO_EPS_DISTINGUISHER_UP_INT_ALG

@unique
class EEA(IntEnum): # encryption algorithm id for nas/rrc/up
    EEA0 = 0 # no encryption
    EEA1 = 1 # SNOW3G
    EEA2 = 2 # AES-128
    EEA3 = 3 # ZUC

@unique
class EIA(IntEnum): # integrity algorithm id for nas/rrc/up
    EIA0 = 0 # no integrity
    EIA1 = 1 # SNOW3G
    EIA2 = 2 # AES-CMAC
    EIA3 = 3 # ZUC

@dataclass(frozen=True)
class SimProfile:
    imsi: bytes
    k: bytes      # 16B
    opc: bytes    # 16B
    amf: bytes = b"\x90\x01" # idk??

class SessionState:
    def __init__(self, rand, mcc, mnc, sqn, nas_ul_cnt, enc_alg_id, int_alg_id):
        self.rand = rand
        self.mcc = mcc
        self.mnc = mnc
        self.sqn = sqn.to_bytes(6, "big")
        self.nas_ul_cnt = nas_ul_cnt
        self.enc_alg_id = enc_alg_id
        self.int_alg_id = int_alg_id

@dataclass(frozen=True)
class DerivedKeys:
    ck: bytes = b""
    ik: bytes = b""
    ak: bytes = b""
    res: bytes = b""
    k_asme: bytes = b""
    k_nas_enc: bytes = b""
    k_nas_int: bytes = b""
    k_enb: bytes = b""

class Milenage:
    def __init__(self, k, opc):
        self.k = k
        self.opc = opc
        self.cipher = AES.new(k, AES.MODE_ECB)

    def f2345(self, rand):
        opc = self.opc
        cipher = self.cipher

        input = bytearray(x ^ y for x, y in zip(rand, opc))
        temp = cipher.encrypt(bytes(input))

        input = bytearray(x ^ y for x, y in zip(temp, opc))
        input[15] ^= 1

        out = cipher.encrypt(bytes(input))
        out = bytes(x ^ y for x, y in zip(out, opc))

        res = out[8:16]
        ak = out[0:6]

        input = bytearray(x ^ y for x, y in zip(temp, opc))
        input[:16] = input[-12:] + input[:-12]
        input[15] ^= 2

        out = cipher.encrypt(bytes(input))
        out = bytes(x ^ y for x, y in zip(out, opc))

        ck = out[:16]

        input = bytearray(x ^ y for x, y in zip(temp, opc))
        input[:16] = input[-8:] + input[:-8]
        input[15] ^= 4

        out = cipher.encrypt(bytes(input))
        out = bytes(x ^ y for x, y in zip(out, opc))

        ik = out[:16]

        print(f"User CK: {ck.hex()}")
        print(f"User IK: {ik.hex()}")
        print(f"User AK: {ak.hex()}")

        return (ck, ik, ak, res)


class KeyDeriver:

    @staticmethod
    def security_generate_k_asme(ck, ik, ak_xor_sqn, mcc, mnc):
        """ck, ik, mcc, mnc -> k_asme"""
        key = ck + ik

        sn = bytearray(3)

        sn[0] = (mcc & 0x00F0) | ((mcc & 0x0F00) >> 8)
        if (mnc & 0xFF00) == 0xFF00:
            sn[1] = 0xF0 | (mcc & 0x000F)
            sn[2] = ((mnc & 0x000F) << 4) | ((mnc & 0x00F0) >> 4)
        else:
            sn[1] = ((mnc & 0x000F) << 4) | (mcc & 0x000F)
            sn[2] = (mnc & 0x00F0) | ((mnc & 0x0F00) >> 8)
        
        k_asme = kdf_common(FC.K_ASME, key, sn, ak_xor_sqn)

        print(f"k_asme: {k_asme.hex()}")
        return k_asme
    
    @staticmethod
    def security_generate_k_nas(k_asme, ca, ia):
        key = k_asme
        ad = bytes([AlgoType.NAS_ENC])
        ai = bytes([ca])

        k_nas_enc = kdf_common(FC.ALGO_KEY, key, ad, ai)
        print(f"k_nas_enc: {k_nas_enc.hex()}")

        ad = bytes([AlgoType.NAS_INT])
        ai = bytes([ia])

        k_nas_int = kdf_common(FC.ALGO_KEY, key, ad, ai)
        print(f"k_nas_int: {k_nas_int.hex()}")

        return (k_nas_enc, k_nas_int)
    
    @staticmethod
    def security_generate_k_enb(k_asme, nas_count):
        key = k_asme
        nc = bytearray(4)
        
        nc[0] = (nas_count >> 24) & 0xFF;
        nc[1] = (nas_count >> 16) & 0xFF;
        nc[2] = (nas_count >> 8) & 0xFF;
        nc[3] = nas_count & 0xFF;
    
        k_enb = kdf_common(FC.K_ENB, key, nc)
        print(f"k_enb: {k_enb.hex()}")

        return k_enb

    
def kdf_common(fc: int, key: bytes, *params: bytes, out_len: int = 32) -> bytes:
    """
    Generic 3GPP KDF:
    S = FC || P0 || L0 || P1 || L1 [|| P2 || L2 ...]
    result = HMAC-SHA-256(key, S)[:out_len]
    """
    if not (0 <= fc <= 0xFF):
        raise ValueError("fc must be 0..255")
    key = bytes(key)
    s = bytearray([fc])
    for p in params:
        p = bytes(p)
        s += p + len(p).to_bytes(2, "big")
    return hmac.new(key, s, hashlib.sha256).digest()[:out_len]

class SecurityManager:
    def __init__(self, sim:SimProfile):
        self.sim = sim
        self.milenage = Milenage(sim.k, sim.opc)

    def derive_all(self, session:SessionState):
        ck, ik, ak, res = self.milenage.f2345(session.rand)
        ak_xor_sqn = bytes(x ^ y for x, y in zip(ak, session.sqn))


        k_asme = KeyDeriver.security_generate_k_asme(
            ck, ik, ak_xor_sqn, session.mcc, session.mnc
        )
        k_nas_enc, k_nas_int = KeyDeriver.security_generate_k_nas(k_asme, session.enc_alg_id, session.int_alg_id)
        k_enb = KeyDeriver.security_generate_k_enb(k_asme, session.nas_ul_cnt)

        return DerivedKeys(
            ck=ck, ik=ik, ak=ak, res=res,
            k_asme=k_asme, k_nas_enc=k_nas_enc, k_nas_int=k_nas_int, k_enb=k_enb
        )

if __name__ == "__main__":
    sim = SimProfile(
        imsi=b"001010000023448",
        k=bytes.fromhex("ca7c55125829396d335bd8dbcdcde151"),
        opc=bytes.fromhex("d93b00efeaf0bb4e77c060e641497b4d"),
    )

    session = SessionState(
        rand=bytes.fromhex("26b82cb5d36e3d7905f46cabc93534a1"),
        mcc=0xf001,
        mnc=0xff01,
        sqn=0x3e0,
        nas_ul_cnt=0,
        enc_alg_id=EEA.EEA2,
        int_alg_id=EIA.EIA1,
    )

    mgr = SecurityManager(sim)
    keys = mgr.derive_all(session)