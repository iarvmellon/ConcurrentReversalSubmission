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
        f"amount={parsed['amount'] or '-'} RC={rc} ({rc_text})"
    )
    if parsed["message_text"]:
        print(f"{label}: text={parsed['message_text']}")


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
        sequence_number = (
            f"{previous_sequence[:6]}{(int(previous_sequence[6:]) + 10) % 10000:04d}"
        )
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

    # SPDH transmission number is fixed to 00 for every SALE/CLOSE request.
    transmission_number = "00"
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
            increment_batch=increment_batch,
            tid=tid,
        )


def save_next_sale_numbers(
    tid: str,
    sent_sequence_number: str,
    *,
    increment_batch: bool,
) -> None:
    """Persist the next SALE values after the current SALE has been executed."""
    with STATE_LOCK:
        next_suffix = (int(sent_sequence_number[6:]) + 10) % 10000
        next_sequence = f"{sent_sequence_number[:6]}{next_suffix:04d}"
        if increment_batch:
            next_batch = int(next_sequence[3:6]) % 999 + 1
            next_sequence = (
                f"{next_sequence[:3]}{next_batch:03d}{next_sequence[6:]}"
            )

        next_state = {
            "sequence_number": next_sequence,
            "transmission_number": "00",
        }
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


def response_summary(payload: bytes) -> str:
    parsed = parse_spdh(payload)
    if "error" in parsed:
        return parsed["error"]

    rc = parsed["response_code"]
    rc_text = RESPONSE_CODES.get(rc, "Unknown response code")
    text = parsed["message_text"]
    extra = f", text={text}" if text else ""
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


def send_one_packet(
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
    print(
        f"CLOSE BATCH disabled: skipping request for TID={tid}",
        flush=True,
    )
    return False


def send_packets(host: str, port: int, timeout: float, *, state_file=STATE_FILE,
                 nof_trx, tid, amount, delay_seconds=0.0,
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
        try:
            response = send_one_packet(
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
            save_next_sale_numbers(
                tid,
                sequence_number,
                increment_batch=increment_batch_per_sale,
            )

        if attempt != nof_trx - 1:
            time.sleep(delay_seconds)

    if not send_close_batches:
        print("SEND_CLOSE_BATCHES=False: skipping all CLOSE BATCH requests", flush=True)
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
    parser = argparse.ArgumentParser(description="Send the captured SPDH packet over TCP")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    send_packets(args.host, args.port, args.timeout)
