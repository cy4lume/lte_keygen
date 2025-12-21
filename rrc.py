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

from pycrate_asn1dir import RRCLTE

def print_added_drb_info(rrc_uper: bytes):
    """
    Detect DRB additions (drb-ToAddModList) in RRCConnectionReconfiguration and print:
      - LCID
      - EPS bearer ID
      - RLC mode (AM/UM)
      - SN length (AM default = 12)
    Returns a list of dicts.
    """

    def choice(node):
        # Return (tag, val) if node is a CHOICE-like tuple ('tag', val), else (None, node)
        if isinstance(node, tuple) and len(node) == 2 and isinstance(node[0], str):
            return node[0], node[1]
        return None, node

    def pick_choice(node, expected_tag):
        # Accept either ('expected_tag', val) or {'expected_tag': val}
        t, v = choice(node)
        if t == expected_tag:
            return v
        if isinstance(node, dict) and expected_tag in node:
            return node[expected_tag]
        return None

    def find_first(node, key_name):
        # Iterative DFS for nested dict/list/tuple
        stack = [node]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                if key_name in cur:
                    return cur[key_name]
                stack.extend(cur.values())
            elif isinstance(cur, list):
                stack.extend(cur)
            elif isinstance(cur, tuple):
                stack.extend(cur)
        return None

    dl_dcch = RRCLTE.EUTRA_RRC_Definitions.DL_DCCH_Message
    dl_dcch.from_uper(rrc_uper)
    root = dl_dcch._val

    # message: c1 -> rrcConnectionReconfiguration
    msg = root.get("message")
    msg = pick_choice(msg, "c1") or msg
    rrcc = pick_choice(msg, "rrcConnectionReconfiguration")
    if rrcc is None or not isinstance(rrcc, dict):
        print("Not an RRCConnectionReconfiguration.")
        return []

    # criticalExtensions: c1 -> rrcConnectionReconfiguration-r8
    ce = rrcc.get("criticalExtensions")
    ce = pick_choice(ce, "c1") or ce
    r8 = pick_choice(ce, "rrcConnectionReconfiguration-r8")
    if r8 is None or not isinstance(r8, dict):
        print("No rrcConnectionReconfiguration-r8.")
        return []

    rrcd = r8.get("radioResourceConfigDedicated")
    # radioResourceConfigDedicated is a SEQUENCE, but be tolerant to CHOICE-like wrappers
    _, rrcd = choice(rrcd)
    if not isinstance(rrcd, dict):
        print("No radioResourceConfigDedicated.")
        return []

    drb_add = rrcd.get("drb-ToAddModList")
    if not isinstance(drb_add, list) or not drb_add:
        print("No DRB additions (drb-ToAddModList absent/empty).")
        return []

    out = []
    for i, item in enumerate(drb_add):
        if not isinstance(item, dict):
            continue

        eps_bearer = item.get("eps-BearerIdentity")
        drb_id = item.get("drb-Identity")
        lcid = item.get("logicalChannelIdentity")

        # rlc-Config: am/um choice
        rlc_cfg = item.get("rlc-Config")
        rlc_mode = "UNKNOWN"
        sn_len = None

        # Typical: ('am', {...}) or ('um-Bi-Directional', {...})
        t, v = choice(rlc_cfg)
        if t is None and isinstance(rlc_cfg, dict):
            # Sometimes represented as {'am': {...}} (rare). Pick first known key.
            if "am" in rlc_cfg:
                t, v = "am", rlc_cfg["am"]
            else:
                for k in rlc_cfg.keys():
                    if isinstance(k, str) and k.startswith("um"):
                        t, v = k, rlc_cfg[k]
                        break

        if t == "am":
            rlc_mode = "AM"
            sn_len = 12  # requirement: assume AM default SN length = 12
        elif isinstance(t, str) and t.startswith("um"):
            rlc_mode = "UM"
            snf = find_first(v, "sn-FieldLength")
            if snf == "size5":
                sn_len = 5
            elif snf == "size10":
                sn_len = 10
            elif snf == "size12":
                sn_len = 12
            else:
                sn_len = None
        else:
            # Fallback: if we can't see UM sn-FieldLength, treat as AM=12 for LTE practice
            snf = find_first(rlc_cfg, "sn-FieldLength")
            if snf is not None:
                rlc_mode = "UM"
                sn_len = 5 if snf == "size5" else 10 if snf == "size10" else 12 if snf == "size12" else None
            else:
                rlc_mode = "AM"
                sn_len = 12

        rec = {
            "index": i,
            "drb_id": drb_id,
            "lcid": lcid,
            "eps_bearer": eps_bearer,
            "rlc_mode": rlc_mode,
            "sn_length": sn_len,
        }
        out.append(rec)

        print(
            f"[AddToDRBList] item={i} "
            f"DRB={drb_id} LCID={lcid} EPS_bearer={eps_bearer} "
            f"RLC={rlc_mode} SN_len={sn_len}"
        )

    return out
