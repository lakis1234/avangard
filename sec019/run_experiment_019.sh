#!/usr/bin/env bash
set -euo pipefail

NV_INDEX="0x01500019"
AK_HANDLE="0x81010019"
DATA_PORT="2321"
CONTROL_PORT="2322"
WORK_DIR="$(mktemp -d -t calibre-sec019.XXXXXXXX)"
STATE_DIR="${WORK_DIR}/state"
SNAPSHOT_DIR="${WORK_DIR}/state-generation-1"
RUN_DIR="${WORK_DIR}/run"
PID_FILE="${WORK_DIR}/swtpm.pid"
LOG_FILE="${WORK_DIR}/swtpm.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="${SEC019_EVIDENCE_DIR:-${SCRIPT_DIR}/evidence}"

mkdir -p "${STATE_DIR}" "${RUN_DIR}" "${EVIDENCE_DIR}"
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=${DATA_PORT}"

stop_tpm() {
    if [[ -s "${PID_FILE}" ]]; then
        local pid
        pid="$(cat "${PID_FILE}")"
        if kill -0 "${pid}" 2>/dev/null; then
            tpm2_shutdown -c >/dev/null 2>&1 || true
            kill "${pid}" 2>/dev/null || true
            for _ in $(seq 1 50); do
                if ! kill -0 "${pid}" 2>/dev/null; then
                    break
                fi
                sleep 0.1
            done
        fi
        rm -f "${PID_FILE}"
    fi
}

cleanup() {
    stop_tpm
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

start_tpm() {
    rm -f "${PID_FILE}"
    swtpm socket \
        --tpm2 \
        --tpmstate "dir=${STATE_DIR}" \
        --server "type=tcp,port=${DATA_PORT},bindaddr=127.0.0.1" \
        --ctrl "type=tcp,port=${CONTROL_PORT},bindaddr=127.0.0.1" \
        --flags not-need-init,startup-clear \
        --pid "file=${PID_FILE}" \
        --log "file=${LOG_FILE},level=2" \
        --daemon

    for _ in $(seq 1 50); do
        if tpm2_getcap properties-fixed >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    echo "SEC-019 ERROR: swtpm did not become ready" >&2
    cat "${LOG_FILE}" >&2 || true
    return 1
}

counter_value() {
    tpm2_nvread -C o "${NV_INDEX}" --print-yaml |
        awk '/^counter:/ {print $2}'
}

nv_name() {
    tpm2_nvreadpublic "${NV_INDEX}" |
        awk '/^[[:space:]]+name:/ {print $2; exit}'
}

make_nonce() {
    local label="$1"
    local output="$2"
    printf '%s' "CALIBRE-SEC019:${label}" | openssl dgst -sha256 -binary > "${output}"
}

certify() {
    local label="$1"
    local nonce_file="$2"
    local generation="$3"
    local pinned_name="$4"
    local attestation="${RUN_DIR}/${label}.attestation.bin"
    local signature="${RUN_DIR}/${label}.signature.bin"

    tpm2_nvcertify \
        -C "${AK_HANDLE}" \
        -c o \
        -g sha256 \
        -s rsassa \
        -f plain \
        -q "${nonce_file}" \
        -o "${signature}" \
        --attestation "${attestation}" \
        --size 8 \
        "${NV_INDEX}"

    openssl dgst \
        -verify "${RUN_DIR}/ak-public.pem" \
        -keyform pem \
        -sha256 \
        -signature "${signature}" \
        "${attestation}" >/dev/null

    python3 "${SCRIPT_DIR}/verify_attestation.py" \
        --attestation "${attestation}" \
        --nonce "${nonce_file}" \
        --generation "${generation}" \
        --nv-name "${pinned_name}" \
        --json-out "${RUN_DIR}/${label}.attestation.json"
}

echo "CALIBRE SECURITY SEC-019 v0.19.0"
echo "ISOLATED SWT TPM2 NV COUNTER / NONCE-BOUND NV_CERTIFY / HOST-SNAPSHOT ROLLBACK"
echo "One ephemeral swtpm instance; actual TPM2_NV_Increment and TPM2_NV_Certify command paths"
echo "Purpose: replace SEC-018's abstract generation proof with decoded, signature-verified TPM2 attestations"
echo "Host physical TPM / PCR / NV / hierarchy / Secure Boot / BitLocker: NOT ACCESSED"
echo

start_tpm

tpm2_createek -Q -G rsa -c "${RUN_DIR}/ek.ctx" -u "${RUN_DIR}/ek.pub"
tpm2_createak \
    -Q \
    -C "${RUN_DIR}/ek.ctx" \
    -G rsa \
    -g sha256 \
    -s rsassa \
    -c "${RUN_DIR}/ak.ctx" \
    -u "${RUN_DIR}/ak.pub" \
    -n "${RUN_DIR}/ak.name"
tpm2_evictcontrol -Q -C o -c "${RUN_DIR}/ak.ctx" "${AK_HANDLE}"
tpm2_readpublic -c "${AK_HANDLE}" -f pem -o "${RUN_DIR}/ak-public.pem" \
    > "${RUN_DIR}/ak-public.yml"

for attribute in restricted sign fixedtpm fixedparent sensitivedataorigin; do
    if ! grep -q "${attribute}" "${RUN_DIR}/ak-public.yml"; then
        echo "SEC-019 ERROR: AK lacks required ${attribute} attribute" >&2
        exit 1
    fi
done
echo "SWT TPM ATTESTATION KEY: RESTRICTED SIGNING + FIXEDTPM + FIXEDPARENT + SENSITIVEDATAORIGIN -> PASS"

tpm2_nvdefine -Q -C o -s 8 -a "nt=counter|ownerread|ownerwrite" "${NV_INDEX}"
tpm2_nvincrement -Q -C o "${NV_INDEX}"
GENERATION_1="$(counter_value)"
if [[ "${GENERATION_1}" != "1" ]]; then
    echo "SEC-019 ERROR: first counter generation is ${GENERATION_1}, expected 1" >&2
    exit 1
fi
PINNED_NV_NAME="$(nv_name)"
if [[ ! "${PINNED_NV_NAME}" =~ ^[[:xdigit:]]{68}$ ]]; then
    echo "SEC-019 ERROR: unexpected NV Name ${PINNED_NV_NAME}" >&2
    exit 1
fi
printf '%s\n' "${PINNED_NV_NAME}" > "${RUN_DIR}/pinned-nv-name.txt"
make_nonce "GENERATION-1" "${RUN_DIR}/generation-1.nonce.bin"
certify "generation-1" "${RUN_DIR}/generation-1.nonce.bin" "${GENERATION_1}" "${PINNED_NV_NAME}"
echo "GENERATION 1 NV_CERTIFY: RSA SIGNATURE + TPM MAGIC/TYPE + NONCE + NV NAME + COUNTER VALUE -> PASS"

stop_tpm
cp -a "${STATE_DIR}" "${SNAPSHOT_DIR}"
start_tpm

tpm2_nvincrement -Q -C o "${NV_INDEX}"
GENERATION_2="$(counter_value)"
if (( GENERATION_2 <= GENERATION_1 )); then
    echo "SEC-019 ERROR: counter did not increase (${GENERATION_1} -> ${GENERATION_2})" >&2
    exit 1
fi
make_nonce "GENERATION-2" "${RUN_DIR}/generation-2.nonce.bin"
certify "generation-2" "${RUN_DIR}/generation-2.nonce.bin" "${GENERATION_2}" "${PINNED_NV_NAME}"
echo "PERSISTENT COUNTER ACROSS SWT TPM RESTART: ${GENERATION_1}->${GENERATION_2} -> PASS"
echo "GENERATION ${GENERATION_2} FRESH NV_CERTIFY: SIGNATURE AND ALL BINDINGS -> PASS"

if python3 "${SCRIPT_DIR}/verify_attestation.py" \
    --attestation "${RUN_DIR}/generation-1.attestation.bin" \
    --nonce "${RUN_DIR}/generation-2.nonce.bin" \
    --generation "${GENERATION_2}" \
    --nv-name "${PINNED_NV_NAME}" >/dev/null 2>&1; then
    echo "SEC-019 ERROR: stale generation-1 attestation replay was accepted" >&2
    exit 1
fi
echo "OLD GENERATION-1 ATTESTATION REPLAYED AS GENERATION-${GENERATION_2}: NONCE/VALUE CHECK REJECTED -> PASS"

tpm2_nvundefine -Q -C o "${NV_INDEX}"
tpm2_nvdefine -Q -C o -s 8 -a "nt=counter|ownerread|ownerwrite" "${NV_INDEX}"
tpm2_nvincrement -Q -C o "${NV_INDEX}"
GENERATION_3="$(counter_value)"
REDEFINED_NV_NAME="$(nv_name)"
if [[ "${REDEFINED_NV_NAME}" != "${PINNED_NV_NAME}" ]]; then
    echo "SEC-019 ERROR: identical same-handle definition produced a different NV Name" >&2
    exit 1
fi
if (( GENERATION_3 <= GENERATION_2 )); then
    echo "SEC-019 ERROR: same-Name counter redefine reset (${GENERATION_2} -> ${GENERATION_3})" >&2
    exit 1
fi
make_nonce "GENERATION-REDEFINED" "${RUN_DIR}/generation-redefined.nonce.bin"
certify "generation-redefined" "${RUN_DIR}/generation-redefined.nonce.bin" "${GENERATION_3}" "${PINNED_NV_NAME}"
echo "IDENTICAL SAME-NAME UNDEFINE/REDEFINE: FIRST NEW VALUE ${GENERATION_3} > ${GENERATION_2} -> PASS IN SWT TPM"

stop_tpm
rm -rf "${STATE_DIR}"
cp -a "${SNAPSHOT_DIR}" "${STATE_DIR}"
start_tpm

ROLLED_BACK_GENERATION="$(counter_value)"
ROLLED_BACK_NV_NAME="$(nv_name)"
if [[ "${ROLLED_BACK_GENERATION}" != "${GENERATION_1}" ]]; then
    echo "SEC-019 ERROR: restored snapshot has ${ROLLED_BACK_GENERATION}, expected ${GENERATION_1}" >&2
    exit 1
fi
if [[ "${ROLLED_BACK_NV_NAME}" != "${PINNED_NV_NAME}" ]]; then
    echo "SEC-019 ERROR: restored snapshot changed the pinned NV Name" >&2
    exit 1
fi
make_nonce "AFTER-HOST-SNAPSHOT-ROLLBACK" "${RUN_DIR}/rollback.nonce.bin"
certify "rollback" "${RUN_DIR}/rollback.nonce.bin" "${ROLLED_BACK_GENERATION}" "${PINNED_NV_NAME}"
echo "FULL SWT TPM HOST-STATE SNAPSHOT RESTORE: ${GENERATION_3}->${ROLLED_BACK_GENERATION}; FRESH OLD-VALUE NV_CERTIFY VALID -> ATTACK WITNESS CONFIRMED"

cp \
    "${RUN_DIR}/ak-public.pem" \
    "${RUN_DIR}/ak-public.yml" \
    "${RUN_DIR}/pinned-nv-name.txt" \
    "${RUN_DIR}"/*.nonce.bin \
    "${RUN_DIR}"/*.attestation.bin \
    "${RUN_DIR}"/*.attestation.json \
    "${RUN_DIR}"/*.signature.bin \
    "${EVIDENCE_DIR}/"
swtpm --version > "${EVIDENCE_DIR}/swtpm-version.txt"
tpm2_nvcertify --version > "${EVIDENCE_DIR}/tpm2-tools-version.txt"

echo
echo "=== SEC-019 DECISION ==="
echo "ACTUAL_TPM2_NV_INCREMENT_COMMAND_PATH=PASS_IN_ISOLATED_SWT_TPM"
echo "ACTUAL_TPM2_NV_CERTIFY_SIGNATURE_NONCE_NAME_VALUE_BINDING=PASS_IN_ISOLATED_SWT_TPM"
echo "PERSISTENT_COUNTER_ACROSS_SWT_TPM_RESTART=PASS_${GENERATION_1}_TO_${GENERATION_2}"
echo "IDENTICAL_SAME_NAME_NV_REDEFINE_DOES_NOT_RESET_COUNTER=PASS_${GENERATION_2}_TO_${GENERATION_3}"
echo "OLD_ATTESTATION_REPLAY_FOR_NEW_NONCE_AND_GENERATION=REJECTED"
echo "FULL_SWT_TPM_HOST_STATE_SNAPSHOT_ROLLBACK=STALE_GENERATION_${ROLLED_BACK_GENERATION}_FRESHLY_CERTIFIED_ATTACK_CONFIRMED"
echo "PHYSICAL_TPM_MONOTONICITY_POWER_LOSS_AND_SEVEN_MACHINE_QUORUM=NOT_TESTED"
echo "HOST_PHYSICAL_TPM_PCR_NV_HIERARCHY_SECURE_BOOT_BITLOCKER_ACCESSED=NO"
echo "GLOBAL_BLOCKCHAIN_OR_UNIVERSAL_ORDER_USED=NO"
