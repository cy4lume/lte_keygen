from binascii import unhexlify
from pycrate_asn1dir import RRCLTE
from key import *

def _find_nas_parents(node, parent=None, parent_key=None):
    """
    Yields (parent_container, key_or_index, nas_bytes, style)

    style:
      - 'choice_tuple' : parent[key] == ('dedicatedInfoNAS', nas_bytes)
      - 'dict_key'     : parent['dedicatedInfoNAS'] == nas_bytes
      - 'list_item'    : parent[index] == nas_bytes (inside dedicatedInfoNASList)
    """
    if isinstance(node, dict):
        # Direct key case: dedicatedInfoNAS
        if "dedicatedInfoNAS" in node and isinstance(node["dedicatedInfoNAS"], (bytes, bytearray)):
            yield (node, "dedicatedInfoNAS", bytes(node["dedicatedInfoNAS"]), "dict_key")

        # SEQUENCE OF case: dedicatedInfoNASList: [bytes, bytes, ...]
        if "dedicatedInfoNASList" in node and isinstance(node["dedicatedInfoNASList"], list):
            lst = node["dedicatedInfoNASList"]
            for i, v in enumerate(lst):
                if isinstance(v, (bytes, bytearray)):
                    yield (lst, i, bytes(v), "list_item")
                else:
                    yield from _find_nas_parents(v, lst, i)

        # Continue traversal
        for k, v in node.items():
            yield from _find_nas_parents(v, node, k)

    elif isinstance(node, list):
        for i, v in enumerate(node):
            # Generic list traversal (covers nested structures)
            if isinstance(v, (bytes, bytearray)):
                # Only yield as NAS if you want heuristic matching here.
                # Safer to only yield list_item via dedicatedInfoNASList branch above.
                pass
            else:
                yield from _find_nas_parents(v, node, i)

    elif isinstance(node, tuple):
        # CHOICE: ('dedicatedInfoNAS', b'...')
        if len(node) == 2 and node[0] == "dedicatedInfoNAS" and isinstance(node[1], (bytes, bytearray)):
            if parent is not None:
                yield (parent, parent_key, bytes(node[1]), "choice_tuple")

        for i, v in enumerate(node):
            yield from _find_nas_parents(v, node, i)


def decipher_nas(nas: bytes, k_nas_enc: bytes, direction: int) -> bytes:
    # EPS security protected NAS:
    # [0] SHT+PD, [1:5] MAC, [5] SN, [6:] ciphered NAS message
    seq = nas[5]
    deciphered = liblte_security_encryption_eea2(
        k_nas_enc[16:],
        seq,
        0,
        direction,
        nas[6:],
        len(nas[6:]) * 8
    )
    result = nas[0:6] + deciphered
    return result


def process_nas_by_rrc(rrc: bytes, k_nas_enc: bytes, direction: int) -> bytes:
    dl_dcch = RRCLTE.EUTRA_RRC_Definitions.DL_DCCH_Message
    dl_dcch.from_uper(rrc)
    tree = dl_dcch._val

    found = False
    for parent, key, nas_bytes, style in _find_nas_parents(tree):
        found = True
        new_nas = decipher_nas(nas_bytes, k_nas_enc, direction)

        if style == "dict_key":
            parent[key] = new_nas
            break
        elif style == "choice_tuple":
            parent[key] = ("dedicatedInfoNAS", new_nas)
            break
        elif style == "list_item":
            parent[key] = new_nas
            break

    print("NAS found:", found)

    if found:
        return dl_dcch.to_uper()
    return rrc
