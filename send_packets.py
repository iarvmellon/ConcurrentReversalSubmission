import json
import argparse
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

STATE_FILE = Path(__file__).with_name("sales_transmitted.json")
NEXT_PACKET_FILE = Path(__file__).with_name("next_TRX_per_TID.json")
STATE_LOCK = threading.RLock()
RUNTIME_TID_STATES = {}
ALLOWED_SALE_TID = "00003971"
REVERSALS_ENABLED = False

RESPONSE_CODES = {
    "000": "Approved",
    "001": "Approved, no balances available",
    "078": "Duplicate transaction received",
    "095": "Amount over maximum",
    "898": "Invalid MAC",
    "899": "Sequence error - resynchronization required",
}

# Exact 307-byte TCP application payload from frame 15 of stress.pcap.
# Template values from the capture are replaced by the constants above before
# the bytes are sent.
CAPTURED_PAYLOAD = bytes.fromhex("""
0131392e333630303030303030332020202020202020202020202020323630373037313432303034
464f30303135303030301c42303030311c44301c55301c6530301c68303031303835303035301c71
3b343033333035303037323633333537393d33303033323031313030303032323631303030303f1c
361e453037311e493937381e4f303138303030383236303730373636453545373541373930324139
46343030303030313634363141313636394430303030303030303030303039373830303030303030
303530303030363032313230334130303030301e50303130313232303230303030303039364130
3030303030303033313031301e71303139463645303432303730303030301e583030303030301e30
302020202032302020201c391e423036331c47393146413443344203
""")

# Timeout reversal template with message subtype T.
CAPTURED_PAYLOAD_REVERSAL = bytes.fromhex("""
0131392e333630303030303030332020202020202020202020202020323630373037313432303034
465430303135303030301c42303030311c44301c55301c6530301c68303031303835303035301c71
3b343033333035303037323633333537393d33303033323031313030303032323631303030303f1c
361e453037311e493937381e4f303138303030383236303730373636453545373541373930324139
46343030303030313634363141313636394430303030303030303030303039373830303030303030
303530303030363032313230334130303030301e50303130313232303230303030303039364130
3030303030303033313031301e71303139463645303432303730303030301e583030303030301e30
302020202032302020201c391e423036331c47393146413443344203
""")

# Exact CLOSE BATCH request captured on the wire. Dynamic header, totals, and
# sequence fields are replaced before transmission.
CLOSE_BATCH_PAYLOAD = bytes.fromhex("""
009b392e333930303030343232322020202020202020202020202020323630373135313133343531
414f36303035303030301c6c303031303030303030322b3030303030303030303030303030303035
39303030302b303030303030303030303030303030303030303030312b3030303030303030303030
303030303030311c68303031303230303133311c391e423036331c47344138394637434403
""")


def parse_spdh(payload: bytes) -> dict[str, str]:
    if len(payload) >= 2 and int.from_bytes(payload[:2], "big") == len(payload) - 2:
        body = payload[2:]
    else:
        body = payload

    if len(body) < 48:
        return {"error": f"SPDH body too short ({len(body)} bytes)"}

    header = body[:48].decode("ascii", errors="replace")
    fields = {}
    for part in body[48:].rstrip(b"\x03").split(b"\x1c"):
        if not part:
            continue
        key = chr(part[0])
        fields[key] = part[1:].decode("ascii", errors="replace")

    batch_totals = fields.get("l", "")
    batch_debit_count = ""
    batch_debit_amount = ""
    if len(batch_totals) == 75:
        batch_debit_count = batch_totals[6:10]
        batch_debit_amount = batch_totals[10:29]

    return {
        "transmission": header[2:4],
        "tid": header[4:12],
        "date": header[26:32],
        "time": header[32:38],
        "message": header[38:40],
        "transaction_code": header[40:42],
        "processing_flags": header[42:45],
        "response_code": header[45:48],
        "sequence": fields.get("h", ""),
        "amount": fields.get("B", ""),
        "approval_code": fields.get("F", "").strip(),
        "rrn": fields.get("i", "").strip(),
        "message_text": fields.get("g", ""),
        "batch_debit_count": batch_debit_count,
        "batch_debit_amount": batch_debit_amount,
    }


def print_spdh_summary(label: str, payload: bytes) -> None:
    parsed = parse_spdh(payload)
    if "error" in parsed:
        print(f"{label}: {parsed['error']}")
        return

    rc = parsed["response_code"]
    rc_text = RESPONSE_CODES.get(rc, "Unknown response code")
    print(
        f"{label}: transmission={parsed['transmission']} "
        f"TID={parsed['tid']} seq={parsed['sequence'] or '-'} "
        f"transaction_code={parsed['transaction_code']} "
        f"amount={parsed['amount'] or '-'} RC={rc} ({rc_text})"
    )
    if parsed["message_text"]:
        print(f"{label}: text={parsed['message_text']}")
    if parsed["rrn"]:
        print(f"{label}: RRN={parsed['rrn']}")


def remove_captured_mac(payload: bytearray) -> None:
    mac_start = payload.rfind(b"\x1cG")
    if mac_start == -1:
        return
    del payload[mac_start:-1]
    payload[:2] = (len(payload) - 2).to_bytes(2, "big")


def load_state(
    state_file: Path,
    initial_sequence_number: str,
    initial_transmission_number: str,
) -> dict[str, str]:
    if not state_file.exists():
        return {
            "next_sequence_number": initial_sequence_number,
            "next_transmission_number": initial_transmission_number,
        }

    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Recover an empty/corrupt state file from configured initial values.
        return {
            "next_sequence_number": initial_sequence_number,
            "next_transmission_number": initial_transmission_number,
        }
    if isinstance(state, list):
        if not state:
            return {"next_sequence_number": initial_sequence_number,
                    "next_transmission_number": initial_transmission_number}
        last = state[-1]
        seq = last["sequence_number"]
        suffix = (int(seq[6:]) + 10) % 10000
        return {"next_sequence_number": f"{seq[:6]}{suffix:04d}",
                "next_transmission_number": f"{(int(last['transmission_number']) + 1) % 100:02d}",
                "history": state}
    sequence_number = state.get("next_sequence_number", "")
    transmission_number = state.get("next_transmission_number", "")
    if len(sequence_number) != 10 or not sequence_number.isdigit():
        raise ValueError(f"Invalid sequence number in {state_file}")
    if len(transmission_number) != 2 or not transmission_number.isdigit():
        raise ValueError(f"Invalid transmission number in {state_file}")
    return state


def save_state(state: dict[str, str], state_file: Path = STATE_FILE) -> None:
    temporary_file = state_file.with_suffix(state_file.suffix + ".tmp")
    payload = state.get("history", [])
    temporary_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary_file.replace(state_file)


def remove_pending_sale(
    state_file: Path,
    sequence_number: str,
    tid: Optional[str],
) -> bool:
    """Remove one SALE only after its own TID/sequence CLOSE succeeds."""
    with STATE_LOCK:
        recorded = json.loads(state_file.read_text(encoding="utf-8"))
        history = recorded if isinstance(recorded, list) else recorded.get("history", [])
        removed = False
        remaining = []
        for entry in history:
            if (
                not removed
                and entry.get("sequence_number") == sequence_number
                and entry.get("tid") == tid
            ):
                removed = True
                continue
            remaining.append(entry)
        if removed:
            save_state({"history": remaining}, state_file)
        return removed


def prepare_run_state(
    state_file: Path,
    initial_sequence_number: str,
    initial_transmission_number: str,
    increment_batch_per_sale: bool,
) -> dict[str, str]:
    state_exists = state_file.exists()
    state = load_state(state_file, initial_sequence_number, initial_transmission_number)
    if state_exists and not increment_batch_per_sale:
        sequence_number = state["next_sequence_number"]
        next_batch_number = int(sequence_number[3:6]) % 999 + 1
        state["next_sequence_number"] = (
            f"{sequence_number[:3]}{next_batch_number:03d}{sequence_number[6:]}"
        )
        save_state(state, state_file)
    return state


def _reserve_message_numbers(
    state_file: Path,
    initial_sequence_number: str,
    initial_transmission_number: str,
    *,
    record: bool = True,
    increment_sequence: bool = True,
    increment_batch: bool = False,
    tid=None,
) -> tuple[str, str]:
    state_key = tid or "default"
    try:
        recorded = json.loads(state_file.read_text(encoding="utf-8"))
        history = recorded if isinstance(recorded, list) else recorded.get("history", [])
    except (OSError, json.JSONDecodeError):
        history = []

    tid_state = RUNTIME_TID_STATES.get(state_key)
    if tid_state is not None:
        previous_sequence = tid_state["sequence_number"]
        if increment_sequence:
            sequence_number = (
                f"{previous_sequence[:6]}"
                f"{(int(previous_sequence[6:]) + 10) % 10000:04d}"
            )
        else:
            sequence_number = previous_sequence
        previous_transmission = tid_state["transmission_number"]
        transmission_number = f"{(int(previous_transmission) + 1) % 100:02d}"
        if increment_batch:
            next_batch_number = int(sequence_number[3:6]) % 999 + 1
            sequence_number = (
                f"{sequence_number[:3]}{next_batch_number:03d}{sequence_number[6:]}"
            )
    else:
        configured_state = None
        try:
            candidate = json.loads(NEXT_PACKET_FILE.read_text(encoding="utf-8"))
            if isinstance(candidate, dict):
                configured_state = candidate
        except (OSError, json.JSONDecodeError):
            pass
        if configured_state:
            # Values in next_TRX_per_TID.json are the exact next values to send.
            sequence_number = configured_state["sequence_number"]
            transmission_number = configured_state["transmission_number"]
        else:
            history_state = None
            for entry in reversed(history):
                if (entry.get("tid") or "default") == state_key:
                    history_state = entry
                    break
            if history_state:
                previous_sequence = history_state["sequence_number"]
                sequence_number = (
                    f"{previous_sequence[:6]}"
                    f"{(int(previous_sequence[6:]) + 10) % 10000:04d}"
                )
                previous_transmission = history_state["transmission_number"]
                transmission_number = f"{(int(previous_transmission) + 1) % 100:02d}"
                if increment_batch:
                    next_batch_number = int(sequence_number[3:6]) % 999 + 1
                    sequence_number = (
                        f"{sequence_number[:3]}{next_batch_number:03d}"
                        f"{sequence_number[6:]}"
                    )
            else:
                sequence_number = initial_sequence_number
                transmission_number = initial_transmission_number

    next_sequence_suffix = int(sequence_number[6:]) + 10
    sequence_width = len(sequence_number) - 6
    # Adding 10 advances the three-digit rcncltPrdId at positions 6..8,
    # while the final sequence digit remains unchanged.
    next_sequence_suffix %= 10 ** sequence_width
    next_sequence_number = (
        f"{sequence_number[:6]}{next_sequence_suffix:0{sequence_width}d}"
    )
    next_transmission_number = f"{(int(transmission_number) + 1) % 100:02d}"
    if record:
        entry = {
            "sequence_number": sequence_number,
            "transmission_number": transmission_number,
            "saved_at": datetime.now().isoformat(timespec="seconds"),
        }
        if tid is not None:
            entry["tid"] = tid
        history.append(entry)
    save_state(
        {
            "next_sequence_number": next_sequence_number,
            "next_transmission_number": next_transmission_number,
            "history": history,
        },
        state_file,
    )
    RUNTIME_TID_STATES[state_key] = {
        "sequence_number": sequence_number,
        "transmission_number": transmission_number,
    }
    return sequence_number, transmission_number


def reserve_message_numbers(
    state_file: Path,
    initial_sequence_number: str,
    initial_transmission_number: str,
    *,
    record: bool = True,
    increment_sequence: bool = True,
    increment_batch: bool = False,
    tid=None,
) -> tuple[str, str]:
    """Reserve unique counters safely when multiple TID threads are running."""
    with STATE_LOCK:
        return _reserve_message_numbers(
            state_file,
            initial_sequence_number,
            initial_transmission_number,
            record=record,
            increment_sequence=increment_sequence,
            increment_batch=increment_batch,
            tid=tid,
        )


def save_next_sale_numbers(
    tid: str,
    sent_sequence_number: str,
    sent_transmission_number: str,
    *,
    increment_sequence: bool = True,
    increment_batch: bool,
    reset_transmission: bool = False,
) -> None:
    """Persist the next SALE values after the current SALE has been executed."""
    with STATE_LOCK:
        if increment_sequence:
            next_suffix = (int(sent_sequence_number[6:]) + 10) % 10000
            next_sequence = f"{sent_sequence_number[:6]}{next_suffix:04d}"
        else:
            next_sequence = sent_sequence_number
        if increment_batch:
            next_batch = int(next_sequence[3:6]) % 999 + 1
            next_sequence = (
                f"{next_sequence[:3]}{next_batch:03d}{next_sequence[6:]}"
            )

        next_state = {
            "sequence_number": next_sequence,
            "transmission_number": (
                "00"
                if reset_transmission
                else f"{(int(sent_transmission_number) + 1) % 100:02d}"
            ),
        }
        if reset_transmission and tid in RUNTIME_TID_STATES:
            # The next in-process reservation increments 99 to 00.
            RUNTIME_TID_STATES[tid]["transmission_number"] = "99"
        temporary_file = NEXT_PACKET_FILE.with_suffix(
            NEXT_PACKET_FILE.suffix + ".tmp"
        )
        temporary_file.write_text(
            json.dumps(next_state, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary_file.replace(NEXT_PACKET_FILE)


def snapshot_tid_state(tid: str):
    """Return a copy of the current in-process counters for one TID."""
    with STATE_LOCK:
        state = RUNTIME_TID_STATES.get(tid)
        return dict(state) if state else None


def rollback_rejected_reservation(
    tid: str,
    rejected_sequence: str,
    previous_tid_state,
) -> None:
    """Restore counters while keeping the transmitted SALE in the history."""
    with STATE_LOCK:
        current = RUNTIME_TID_STATES.get(tid)
        if current and current.get("sequence_number") == rejected_sequence:
            if previous_tid_state is None:
                RUNTIME_TID_STATES.pop(tid, None)
            else:
                RUNTIME_TID_STATES[tid] = previous_tid_state


def is_sequence_rejection(response: dict[str, str]) -> bool:
    """Recognize TANGO responses that reject the transmission/sequence counters."""
    text = response.get("message_text", "").lower()
    return response.get("response_code") == "899" or (
        "invalid" in text and ("transmission" in text or "sequence" in text)
    )


def increment_batch_number(
    state_file: Path,
    initial_sequence_number: str,
    initial_transmission_number: str,
) -> None:
    state = load_state(state_file, initial_sequence_number, initial_transmission_number)
    sequence_number = state["next_sequence_number"]
    next_batch_number = int(sequence_number[3:6]) % 999 + 1
    state["next_sequence_number"] = (
        f"{sequence_number[:3]}{next_batch_number:03d}{sequence_number[6:]}"
    )
    save_state(state, state_file)


def build_payload(
    sequence_number: str,
    transmission_number: str,
    tid: str,
    amount: str,
) -> bytes:
    if len(tid) != 8 or not tid.isdigit():
        raise ValueError("TID must contain exactly 8 digits")
    if len(transmission_number) != 2 or not transmission_number.isdigit():
        raise ValueError("transmission_number must contain exactly 2 digits")
    if len(sequence_number) != 10 or not sequence_number.isdigit():
        raise ValueError("sequence_number must contain exactly 10 digits")
    if len(amount) != 4 or not amount.isdigit():
        raise ValueError("AMOUNT must contain exactly 4 digits")

    payload = bytearray(CAPTURED_PAYLOAD)

    # The transmission number occupies bytes 4..5 in the framed SPDH message.
    payload[4:6] = transmission_number.encode("ascii")

    # TID occupies bytes 6..13 in this SPDH message.
    payload[6:14] = tid.encode("ascii")

    now = datetime.now()
    payload[28:34] = now.strftime("%y%m%d").encode("ascii")
    payload[34:40] = now.strftime("%H%M%S").encode("ascii")

    # Field h contains the sequence number.
    sequence_start = payload.index(b"\x1ch") + 2
    payload[sequence_start:sequence_start + 10] = sequence_number.encode("ascii")

    # Field B contains the transaction amount.
    amount_start = payload.index(b"\x1cB") + 2
    payload[amount_start:amount_start + 4] = amount.encode("ascii")

    # The MAC captured with the original packet is invalid after changing any
    # message data. Omit it unless a real KMAC is available for recalculation.
    remove_captured_mac(payload)

    if int.from_bytes(payload[:2], "big") != len(payload) - 2:
        raise RuntimeError(f"Unexpected SALE payload length: {len(payload)}")
    return bytes(payload)


def build_reversal_payload(
    sale_payload: bytes,
    reversal_sequence_number: str,
    reversal_amount: str,
    approval_code: str,
) -> bytes:
    """Fill a timeout reversal (subtype T) from its SALE."""
    if len(reversal_sequence_number) != 10 or not reversal_sequence_number.isdigit():
        raise ValueError("reversal_sequence_number must contain exactly 10 digits")
    if not reversal_amount or not reversal_amount.isdigit():
        raise ValueError("reversal_amount must contain only digits")

    sale_body = sale_payload[2:]
    sale_header = sale_body[:48]
    sale_fields = {}
    for part in sale_body[48:].rstrip(b"\x03").split(b"\x1c"):
        if part:
            sale_fields[chr(part[0])] = part[1:]

    payload = bytearray(CAPTURED_PAYLOAD_REVERSAL)
    payload[4:6] = sale_header[2:4]
    payload[6:14] = sale_header[4:12]
    now = datetime.now()
    payload[28:34] = now.strftime("%y%m%d").encode("ascii")
    payload[34:40] = now.strftime("%H%M%S").encode("ascii")

    def replace_field(field: bytes, value: bytes) -> None:
        start = payload.index(b"\x1c" + field) + 2
        end = payload.find(b"\x1c", start)
        if end == -1:
            end = len(payload) - 1
        payload[start:end] = value

    replace_field(b"B", reversal_amount.encode("ascii"))
    replace_field(b"h", reversal_sequence_number.encode("ascii"))
    replace_field(b"q", sale_fields["q"])

    # The captured MAC is invalid once dynamic fields have changed.
    remove_captured_mac(payload)
    payload[:2] = (len(payload) - 2).to_bytes(2, "big")
    return bytes(payload)


def build_close_batch_payload(
    transmission_number: str,
    sequence_number: str,
    sale_count: int,
    tid: str,
    amount: str,
) -> bytes:
    """Fill the captured CLOSE BATCH request with current batch values."""
    if len(transmission_number) != 2 or not transmission_number.isdigit():
        raise ValueError("transmission_number must contain exactly 2 digits")
    if len(sequence_number) != 10 or not sequence_number.isdigit():
        raise ValueError("sequence_number must contain exactly 10 digits")
    if len(tid) != 8 or not tid.isdigit():
        raise ValueError("TID must contain exactly 8 digits")
    if sale_count < 0 or sale_count > 9999:
        raise ValueError("sale_count must be between 0 and 9999")
    if not amount or not amount.isdigit():
        raise ValueError("amount must contain only digits")

    payload = bytearray(CLOSE_BATCH_PAYLOAD)
    payload[4:6] = transmission_number.encode("ascii")
    payload[6:14] = tid.encode("ascii")
    now = datetime.now()
    payload[28:34] = now.strftime("%y%m%d").encode("ascii")
    payload[34:40] = now.strftime("%H%M%S").encode("ascii")

    sequence_start = payload.index(b"\x1ch") + 2
    payload[sequence_start:sequence_start + 10] = sequence_number.encode("ascii")

    totals_start = payload.index(b"\x1cl") + 2
    totals_end = payload.index(b"\x1c", totals_start)
    totals = bytearray(payload[totals_start:totals_end])
    totals[6:10] = f"{sale_count:04d}".encode("ascii")
    totals[10:29] = f"+{sale_count * int(amount):018d}".encode("ascii")
    totals[52:56] = b"0000"
    totals[56:75] = b"+000000000000000000"
    payload[totals_start:totals_end] = totals

    remove_captured_mac(payload)
    payload[:2] = (len(payload) - 2).to_bytes(2, "big")
    return bytes(payload)


def increment_sequence_third_component(sequence_number: str) -> str:
    """Increment the third 3-digit component while preserving the final flag."""
    if len(sequence_number) != 10 or not sequence_number.isdigit():
        raise ValueError("sequence_number must contain exactly 10 digits")
    next_component = (int(sequence_number[6:9]) + 1) % 1000
    return f"{sequence_number[:6]}{next_component:03d}{sequence_number[9]}"


def reserve_sale_run(
    state_file: Path,
    initial_sequence_number: str,
    tid: str,
    sale_count: int = 3,
) -> list[tuple[str, str]]:
    """Reserve one batch of SALE counters for a single program run."""
    if sale_count < 1 or sale_count > 100:
        raise ValueError("sale_count must be between 1 and 100")

    with STATE_LOCK:
        try:
            next_packet = json.loads(NEXT_PACKET_FILE.read_text(encoding="utf-8"))
            configured_sales = next_packet.get("sales")
            if isinstance(configured_sales, list) and configured_sales:
                first_sequence = configured_sales[0]["sequence_number"]
                first_transmission = configured_sales[0]["transmission_number"]
            else:
                # Backwards compatibility with the previous state-file format.
                first_sequence = next_packet["sequence_number"]
                first_transmission = next_packet["transmission_number"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            first_sequence = initial_sequence_number
            first_transmission = "00"
            configured_sales = None

        if len(first_sequence) != 10 or not first_sequence.isdigit():
            raise ValueError("sequence_number must contain exactly 10 digits")
        if len(first_transmission) != 2 or not first_transmission.isdigit():
            raise ValueError("transmission_number must contain exactly 2 digits")

        try:
            recorded = json.loads(state_file.read_text(encoding="utf-8"))
            history = recorded if isinstance(recorded, list) else recorded.get("history", [])
        except (OSError, json.JSONDecodeError):
            history = []

        reservations = []
        sequence = first_sequence
        transmission = int(first_transmission)
        if isinstance(configured_sales, list) and len(configured_sales) == sale_count:
            reservations = [
                (sale["sequence_number"], "00")
                for sale in configured_sales
            ]
            sequence = increment_sequence_third_component(reservations[-1][0])

        for _ in range(sale_count - len(reservations)):
            transmission_number = "00"
            reservations.append((sequence, transmission_number))
            history.append(
                {
                    "sequence_number": sequence,
                    "transmission_number": transmission_number,
                    "saved_at": datetime.now().isoformat(timespec="seconds"),
                    "tid": tid,
                }
            )
            sequence = increment_sequence_third_component(sequence)

        save_state({"history": history}, state_file)
        return reservations


def response_summary(payload: bytes) -> str:
    parsed = parse_spdh(payload)
    if "error" in parsed:
        return parsed["error"]

    rc = parsed["response_code"]
    rc_text = RESPONSE_CODES.get(rc, "Unknown response code")
    text = parsed["message_text"]
    extra = f", text={text}" if text else ""
    if parsed["rrn"]:
        extra += f", RRN={parsed['rrn']}"
    if parsed["batch_debit_amount"]:
        extra += (
            f", batch_debit_count={parsed['batch_debit_count']}"
            f", batch_debit_amount={parsed['batch_debit_amount']}"
        )
    return (
        f"transmission={parsed['transmission']} "
        f"seq={parsed['sequence'] or '-'} "
        f"RC={rc} ({rc_text}){extra}"
    )


def send_sale(
    host: str,
    port: int,
    timeout: float,
    sequence_number: str,
    transmission_number: str,
    tid: str,
    amount: str,
) -> dict[str, str]:
    if tid != ALLOWED_SALE_TID:
        raise ValueError(
            f"SALE blocked for TID={tid}; only TID={ALLOWED_SALE_TID} is allowed"
        )
    payload = build_payload(sequence_number, transmission_number, tid, amount)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        source_ip, source_port = sock.getsockname()[:2]
        print(
            f"SALE TID={tid} source={source_ip}:{source_port}",
            flush=True,
        )
        sock.sendall(payload)
        sock.settimeout(timeout)
        response = sock.recv(4096)

    print(f"Response: {response_summary(response)}", flush=True)
    return parse_spdh(response)


def send_sales_in_order(
    host: str,
    port: int,
    timeout: float,
    sales: list[tuple[str, str]],
    tid: str,
    amount: str,
    experiment_delay: float = 0.1,
) -> list[dict[str, str]]:
    """Send SALEs in order and close shortly after transmitting the last one."""
    if tid != ALLOWED_SALE_TID:
        raise ValueError(
            f"SALE blocked for TID={tid}; only TID={ALLOWED_SALE_TID} is allowed"
        )

    ordered_sales = sorted(sales, key=lambda sale: int(sale[0][6:9]))
    components = [int(sequence[6:9]) for sequence, _ in ordered_sales]
    expected_components = list(
        range(components[0], components[0] + len(components))
    )
    if components != expected_components:
        raise ValueError(
            "SALE sequence third components must be consecutive and ordered: "
            f"received={components}, expected={expected_components}"
        )

    responses = []
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        source_ip, source_port = sock.getsockname()[:2]
        for sale_number, (sequence_number, transmission_number) in enumerate(
            ordered_sales, 1
        ):
            transmission_number = "00"
            payload = build_payload(
                sequence_number,
                transmission_number,
                tid,
                amount,
            )
            print(
                f"SALE {sale_number}/{len(ordered_sales)} TID={tid} "
                f"source={source_ip}:{source_port} "
                f"transmission={transmission_number} "
                f"sequence={sequence_number}",
                flush=True,
            )
            sock.sendall(payload)
            if sale_number == len(ordered_sales):
                print(
                    "Last SALE transmitted; closing its connection after "
                    f"experiment_delay={experiment_delay}s",
                    flush=True,
                )
                time.sleep(experiment_delay)
                break
            sock.settimeout(timeout)
            response = sock.recv(4096)
            print(f"Response: {response_summary(response)}", flush=True)
            responses.append(parse_spdh(response))
    finally:
        if sock is not None:
            sock.close()

    return responses


def send_timeout_reversal(
    host: str,
    port: int,
    timeout: float,
    sale_sequence_number: str,
    reversal_sequence_number: str,
    transmission_number: str,
    tid: str,
    amount: str,
) -> dict[str, str]:
    """Send a timeout REVERSAL for the fourth SALE on a new connection."""
    if reversal_sequence_number != sale_sequence_number:
        raise ValueError(
            f"REVERSAL sequence must match SALE sequence {sale_sequence_number}, "
            f"got {reversal_sequence_number}"
        )

    sale_payload = build_payload(
        sale_sequence_number,
        transmission_number,
        tid,
        amount,
    )
    reversal_payload = build_reversal_payload(
        sale_payload,
        reversal_sequence_number,
        amount,
        approval_code="",
    )
    print_spdh_summary("REVERSAL request", reversal_payload)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(reversal_payload)
        sock.settimeout(timeout)
        response = sock.recv(4096)

    print(f"REVERSAL response: {response_summary(response)}", flush=True)
    return parse_spdh(response)


def send_reversal(
    host: str,
    port: int,
    timeout: float,
    sale_sequence_number: str,
    reversal_sequence_number: str,
    transmission_number: str,
    tid: str,
    amount: str,
    approval_code: str,
) -> dict[str, str]:
    if not REVERSALS_ENABLED:
        raise RuntimeError("REVERSAL sending is disabled")
    sale_payload = build_payload(
        sale_sequence_number,
        transmission_number,
        tid,
        amount.zfill(4),
    )
    payload = build_reversal_payload(
        sale_payload,
        reversal_sequence_number,
        amount,
        approval_code,
    )
    parsed_request = parse_spdh(payload)
    if (
        parsed_request.get("message") != "FT"
        or parsed_request.get("transaction_code") != "00"
    ):
        raise RuntimeError(
            "REVERSAL blocked: generated payload is not an FT00 reversal"
        )
    print_spdh_summary("REVERSAL request", payload)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        source_ip, source_port = sock.getsockname()[:2]
        print(
            f"REVERSAL TID={tid} source={source_ip}:{source_port} "
            f"sale_sequence={sale_sequence_number} "
            f"sequence={reversal_sequence_number}",
            flush=True,
        )
        sock.sendall(payload)
        sock.settimeout(timeout)
        response = sock.recv(4096)

    print(f"REVERSAL response: {response_summary(response)}", flush=True)
    return parse_spdh(response)


def send_sale_and_reversal_before_responses(
    host: str,
    port: int,
    timeout: float,
    sale_sequence_number: str,
    reversal_sequence_number: str,
    transmission_number: str,
    tid: str,
    sale_amount: str,
    reversal_amount: str,
    reversal_delay: float = 0.0,
) -> tuple[dict[str, str], dict[str, str]]:
    """Send SALE and its timeout REVERSAL before receiving either response."""
    if not REVERSALS_ENABLED:
        raise RuntimeError("REVERSAL sending is disabled")
    if tid != ALLOWED_SALE_TID:
        raise ValueError(
            f"SALE blocked for TID={tid}; only TID={ALLOWED_SALE_TID} is allowed"
        )
    expected_reversal_sequence = increment_sequence_third_component(
        sale_sequence_number
    )
    if reversal_sequence_number != expected_reversal_sequence:
        raise ValueError(
            "Timeout REVERSAL must increment the SALE sequence third component "
            f"by one: sale={sale_sequence_number}, "
            f"expected={expected_reversal_sequence}, "
            f"reversal={reversal_sequence_number}"
        )

    sale_payload = build_payload(
        sale_sequence_number,
        transmission_number,
        tid,
        sale_amount,
    )
    reversal_payload = build_reversal_payload(
        sale_payload,
        reversal_sequence_number,
        reversal_amount,
        approval_code="",
    )
    parsed_reversal = parse_spdh(reversal_payload)
    if (
        parsed_reversal.get("message") != "FT"
        or parsed_reversal.get("transaction_code") != "00"
        or parsed_reversal.get("transmission") != transmission_number
    ):
        raise RuntimeError(
            "REVERSAL blocked: generated payload is not a matching FT00 reversal"
        )

    sale_socket = socket.create_connection((host, port), timeout=timeout)
    reversal_socket = None
    try:
        sale_source_ip, sale_source_port = sale_socket.getsockname()[:2]
        print(
            f"SALE TID={tid} source={sale_source_ip}:{sale_source_port} "
            f"transmission={transmission_number} "
            f"sequence={sale_sequence_number}",
            flush=True,
        )
        sale_socket.sendall(sale_payload)

        if reversal_delay > 0:
            print(
                f"Waiting {reversal_delay}s before REVERSAL without reading "
                "the SALE response",
                flush=True,
            )
            time.sleep(reversal_delay)

        reversal_socket = socket.create_connection((host, port), timeout=timeout)
        reversal_source_ip, reversal_source_port = reversal_socket.getsockname()[:2]
        print_spdh_summary("REVERSAL request", reversal_payload)
        print(
            f"REVERSAL TID={tid} "
            f"source={reversal_source_ip}:{reversal_source_port} "
            f"sale_sequence={sale_sequence_number} "
            f"sequence={reversal_sequence_number}",
            flush=True,
        )
        reversal_socket.sendall(reversal_payload)
        print(
            "SALE and REVERSAL transmitted; now receiving responses",
            flush=True,
        )

        sale_socket.settimeout(timeout)
        sale_response_payload = sale_socket.recv(4096)
        print(f"SALE response: {response_summary(sale_response_payload)}", flush=True)

        reversal_socket.settimeout(timeout)
        reversal_response_payload = reversal_socket.recv(4096)
        print(
            f"REVERSAL response: {response_summary(reversal_response_payload)}",
            flush=True,
        )
        return (
            parse_spdh(sale_response_payload),
            parse_spdh(reversal_response_payload),
        )
    finally:
        sale_socket.close()
        if reversal_socket is not None:
            reversal_socket.close()


def send_close_batch(
    host: str,
    port: int,
    timeout: float,
    transmission_number: str,
    sequence_number: str,
    sale_count: int,
    tid: str,
    amount: str,
) -> bool:
    payload = build_close_batch_payload(
        transmission_number,
        sequence_number,
        sale_count,
        tid,
        amount,
    )
    print_spdh_summary("CLOSE BATCH request", payload)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)
        sock.settimeout(timeout)
        response = sock.recv(4096)

    print(f"CLOSE BATCH response: {response_summary(response)}", flush=True)
    return parse_spdh(response).get("response_code") in {"000", "001"}


def send_packets(host: str, port: int, timeout: float, *, state_file=STATE_FILE,
                 nof_trx, tid, amount, delay_seconds=0.0,
                 reversal_delay=1.0,
                 close_batch_delay_seconds=0.0, send_close_batches=False,
                 parallel_close_batches=True,
                 increment_batch_per_sale=False, initial_sequence_number,
                 initial_transmission_number) -> None:
    initial_state = prepare_run_state(state_file, initial_sequence_number, initial_transmission_number, increment_batch_per_sale)
    initial_sequence = initial_state["next_sequence_number"]
    print(f"Sales start time: {datetime.now().isoformat(timespec='seconds')}", flush=True)
    print(
        f"Sending {nof_trx} packets to {host}:{port}, every {delay_seconds}s "
        f"with TID={tid}, shift={initial_sequence[:3]}, "
        f"batch=1{initial_sequence[3:6]}, "
        f"rcncltPrdId={initial_sequence[6:9]}, "
        f"start_sequence={initial_sequence}, "
        f"start_transmission={initial_state['next_transmission_number']}, "
        f"amount={amount}",
        flush=True,
    )

    sale_results = []
    for attempt in range(nof_trx):
        previous_tid_state = snapshot_tid_state(tid)
        sequence_number, transmission_number = reserve_message_numbers(
            state_file,
            initial_sequence_number,
            initial_transmission_number,
            increment_batch=increment_batch_per_sale,
            tid=tid,
        )
        print(
            f"[{attempt + 1:03d}/{nof_trx}] "
            f"Sending transmission={transmission_number} "
            f"sequence={sequence_number} batch=1{sequence_number[3:6]} "
            f"rcncltPrdId={sequence_number[6:9]}",
            flush=True,
        )
        sale_approved = False
        sequence_rejected = False
        reversal_sequence_number = None
        reversal_transmission_number = None
        persisted_sequence_number = None
        try:
            response = send_sale(
                host,
                port,
                timeout,
                sequence_number,
                transmission_number, tid, amount,
            )
            sequence_rejected = is_sequence_rejection(response)
            if sequence_rejected:
                rollback_rejected_reservation(
                    tid,
                    sequence_number,
                    previous_tid_state,
                )
                print(
                    f"SALE sequence={sequence_number} rejected by TANGO; "
                    "restored previous counters",
                    flush=True,
                )
            sale_approved = response.get("response_code") in {"000", "001"}
            print(f"SALE sequence={sequence_number} approved={sale_approved}", flush=True)
            approval_code = response.get("approval_code", "")
            if not sequence_rejected:
                # Persist the next TRX immediately after the SALE.
                save_next_sale_numbers(
                    tid,
                    sequence_number,
                    transmission_number,
                    increment_sequence=not (sale_approved and approval_code),
                    increment_batch=(
                        False
                        if sale_approved and approval_code
                        else increment_batch_per_sale
                    ),
                )
                persisted_sequence_number = sequence_number
            if sale_approved and approval_code and REVERSALS_ENABLED:
                print(
                    f"Waiting {reversal_delay}s before REVERSAL "
                    f"for SALE sequence={sequence_number}",
                    flush=True,
                )
                time.sleep(reversal_delay)
                reversal_sequence_number, reversal_transmission_number = (
                    reserve_message_numbers(
                        state_file,
                        initial_sequence_number,
                        initial_transmission_number,
                        record=False,
                        increment_sequence=False,
                        increment_batch=False,
                        tid=tid,
                    )
                )
                reversal_response = send_reversal(
                    host,
                    port,
                    timeout,
                    sequence_number,
                    reversal_sequence_number,
                    reversal_transmission_number,
                    tid,
                    amount,
                    approval_code,
                )
                # Persist the next SALE immediately after the REVERSAL.
                save_next_sale_numbers(
                    tid,
                    reversal_sequence_number,
                    reversal_transmission_number,
                    increment_batch=increment_batch_per_sale,
                    reset_transmission=True,
                )
                persisted_sequence_number = reversal_sequence_number
                reversal_approved = (
                    reversal_response.get("response_code") in {"000", "001"}
                )
                print(
                    f"REVERSAL sequence={reversal_sequence_number} "
                    f"approved={reversal_approved}",
                    flush=True,
                )
            elif sale_approved and not REVERSALS_ENABLED:
                print(
                    f"REVERSAL disabled for SALE sequence={sequence_number}",
                    flush=True,
                )
            elif sale_approved:
                print(
                    f"REVERSAL skipped for SALE sequence={sequence_number}: "
                    "approval code missing from SALE response",
                    flush=True,
                )
            if not sequence_rejected:
                with STATE_LOCK:
                    try:
                        recorded = json.loads(state_file.read_text(encoding="utf-8"))
                        for entry in reversed(recorded if isinstance(recorded, list) else []):
                            if entry.get("sequence_number") == sequence_number:
                                entry["approved"] = sale_approved
                                entry["tid"] = tid
                                break
                        state_file.write_text(json.dumps(recorded, indent=2) + "\n", encoding="utf-8")
                    except (OSError, json.JSONDecodeError):
                        pass
        except socket.timeout:
            print(f"Response: timeout for sequence={sequence_number}", flush=True)
        except OSError as exc:
            print(
                f"Response: socket error for sequence={sequence_number}: {exc}",
                flush=True,
            )
        if not sequence_rejected:
            sale_results.append((sequence_number, sale_approved))
            last_sent_sequence = reversal_sequence_number or sequence_number
            if persisted_sequence_number != last_sent_sequence:
                save_next_sale_numbers(
                    tid,
                    last_sent_sequence,
                    reversal_transmission_number or transmission_number,
                    increment_batch=(
                        increment_batch_per_sale
                        if reversal_sequence_number
                        else False
                    ),
                    reset_transmission=reversal_sequence_number is not None,
                )

        if attempt != nof_trx - 1:
            time.sleep(delay_seconds)

    if not send_close_batches:
        return sale_results

    print(
        f"Waiting {close_batch_delay_seconds}s after the last sale before CLOSE BATCH",
        flush=True,
    )
    time.sleep(close_batch_delay_seconds)

    if increment_batch_per_sale:
        batches_to_close = [
            (sale_sequence, int(sale_approved))
            for sale_sequence, sale_approved in sale_results
        ]
    else:
        batches_to_close = [
            (
                sale_results[0][0],
                sum(int(sale_approved) for _, sale_approved in sale_results),
            )
        ]

    close_requests = []
    close_count = len(batches_to_close)
    for close_attempt, (sale_sequence, approved_count) in enumerate(
        batches_to_close,
        start=1,
    ):
        close_sequence, close_transmission = reserve_message_numbers(
            state_file,
            initial_sequence_number,
            initial_transmission_number,
            record=False,
            tid=tid,
        )
        close_sequence = (
            f"{close_sequence[:3]}{sale_sequence[3:6]}{close_sequence[6:]}"
        )
        print(
            f"[{close_attempt:03d}/{close_count}] "
            f"Closing batch=1{sale_sequence[3:6]} "
            f"rcncltPrdId={sale_sequence[6:9]} "
            f"approved_sales={approved_count} amount={approved_count * int(amount)}",
            flush=True,
        )
        close_requests.append(
            (
                close_attempt,
                close_transmission,
                close_sequence,
                approved_count,
                sale_sequence,
            )
        )

    def send_prepared_close(request: tuple[int, str, str, int, str]) -> bool:
        _, transmission_number, sequence_number, sale_count, sale_sequence = request
        closed = send_close_batch(
            host,
            port,
            timeout,
            transmission_number,
            sequence_number,
            sale_count, tid, amount,
        )
        if closed:
            try:
                removed = remove_pending_sale(
                    state_file,
                    sale_sequence,
                    tid,
                )
                if not removed:
                    print(
                        f"Could not find closed SALE TID={tid} "
                        f"sequence={sale_sequence} in {state_file}",
                        flush=True,
                    )
            except (OSError, json.JSONDecodeError):
                print(
                    f"Could not remove closed SALE TID={tid} "
                    f"sequence={sale_sequence} from {state_file}",
                    flush=True,
                )
        return closed

    if parallel_close_batches:
        start_barrier = threading.Barrier(len(close_requests))

        def send_parallel_close(request: tuple[int, str, str, int, str]) -> bool:
            start_barrier.wait()
            return send_prepared_close(request)

        print(f"Sending all {len(close_requests)} CLOSE BATCH requests together", flush=True)
        with ThreadPoolExecutor(max_workers=len(close_requests)) as executor:
            futures = {
                executor.submit(send_parallel_close, request): request
                for request in close_requests
            }
            for future in as_completed(futures):
                close_attempt, _, _, _, _ = futures[future]
                try:
                    future.result()
                except socket.timeout:
                    print(
                        f"CLOSE BATCH [{close_attempt:03d}] response: timeout",
                        flush=True,
                    )
                except OSError as exc:
                    print(
                        f"CLOSE BATCH [{close_attempt:03d}] response: socket error: {exc}",
                        flush=True,
                    )
    else:
        print(f"Sending {len(close_requests)} CLOSE BATCH requests sequentially for TID={tid}", flush=True)
        for request in close_requests:
            close_attempt, _, _, _, _ = request
            try:
                send_prepared_close(request)
            except socket.timeout:
                print(
                    f"CLOSE BATCH [{close_attempt:03d}] response: timeout",
                    flush=True,
                )
            except OSError as exc:
                print(
                    f"CLOSE BATCH [{close_attempt:03d}] response: socket error: {exc}",
                    flush=True,
                )
    return sale_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send one SPDH SALE over TCP")
    parser.add_argument("--host", default="10.1.110.84")
    parser.add_argument("--port", type=int, default=28420)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--tid", default=ALLOWED_SALE_TID)
    parser.add_argument("--amount", default="0001")
    args = parser.parse_args()

    sequence, transmission = reserve_message_numbers(
        STATE_FILE,
        "0015304720",
        "70",
        increment_batch=True,
        tid=args.tid,
    )
    response = send_sale(
        args.host,
        args.port,
        args.timeout,
        sequence,
        transmission,
        args.tid,
        args.amount,
    )
    approved = response.get("response_code") in {"000", "001"}
    print(f"SALE approved={approved}", flush=True)
    save_next_sale_numbers(
        args.tid,
        sequence,
        transmission,
        increment_batch=True,
    )
