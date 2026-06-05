#!/usr/bin/env bash
# Runs INSIDE the n00b-linux container (invoked by docker/linux-build.sh).
#
# MOUNT-BASED + INCREMENTAL (WP-001 Phase 0).  /src is the host tree mounted
# read-write; nothing is copied.  The Linux n00b build goes into a persistent,
# gitignored build_linux/ under /src, so a second run with no source changes
# rebuilds ~nothing.
#
# ncc: this build tracks crashappsec/ncc via jj (n00b's VCS is jj, never raw
# git).  By default it tracks UPSTREAM `main`; set NCC_REV=<commit|bookmark> to
# pin a specific revision instead (parity with build.sh's NCC_REV).  ncc is
# cloned/fetched into the persistent, gitignored docker/_linux_ncc/ dir and
# built there — fully independent of the host's (out-of-tree) ncc, and selected
# via NCC_PATH (build.sh's ensure_ncc honors an explicit NCC_PATH first).
set -euo pipefail

JOBS="${N00B_JOBS:-2}"

NCC_URL="https://github.com/crashappsec/ncc.git"
NCC_DIR=/src/docker/_linux_ncc          # jj clone of ncc (persisted on host)
NCC_BUILD="${NCC_DIR}/build_linux"      # Linux ncc build dir
# Empty NCC_REV => track upstream main; otherwise pin to the given revision.
NCC_TARGET="${NCC_REV:-main@origin}"
# Headless jj identity (jj needs user.name/email to create the working-copy
# commit on clone/fetch/new; nothing is committed back).
JJ=(jj --config user.name=n00b-ci --config user.email=ci@n00b.local)

# --- ncc: track upstream (or pinned rev) via jj ------------------------------
echo "--- Updating ncc to '${NCC_TARGET}' (jj) ---"
if [[ ${N00B_CLEAN:-0} -ne 0 ]]; then
    rm -rf "${NCC_DIR}"
fi
if [[ ! -d "${NCC_DIR}/.jj" ]]; then
    rm -rf "${NCC_DIR}"
    "${JJ[@]}" git clone "${NCC_URL}" "${NCC_DIR}"
fi
(
    cd "${NCC_DIR}"
    "${JJ[@]}" git fetch
    # Materialize the fetched target (upstream main, or the pinned rev) into the
    # working copy so meson sees those sources on disk.
    "${JJ[@]}" new "${NCC_TARGET}"
)

# --- ncc: build (native Linux), incremental ----------------------------------
echo "--- Building ncc (native Linux, incremental) ---"
if [[ ! -f "${NCC_BUILD}/build.ninja" ]]; then
    CC=clang meson setup --buildtype=release "${NCC_BUILD}" "${NCC_DIR}"
fi
meson compile -C "${NCC_BUILD}" -j "${JOBS}"

# Force the n00b build to use this Linux ncc (NOT any host binary).
export NCC_PATH="${NCC_BUILD}/ncc"

# --- n00b (native Linux), incremental ----------------------------------------
# build.sh build_linux: creates/uses /src/build_linux (persisted on the host).
# When N00B_TEST=1 and a session bus is available, run under dbus-run-session
# with an unlocked keyring so the Secret Service tests exercise the full path
# (test_quic_secret_libsecret SKIPs otherwise).
if [[ "${N00B_TEST:-0}" == "1" ]] && command -v dbus-run-session >/dev/null; then
    cat >/tmp/n00b-dbus-build.sh <<'N00B_DBUS_BUILD'
#!/usr/bin/env bash
set -euo pipefail

# Unlock the keyring with an empty password in headless CI mode.
printf "\n" | gnome-keyring-daemon \
    --start --foreground \
    --components=secrets >/dev/null 2>&1 &

for _ in 1 2 3 4 5; do
    if dbus-send --session --print-reply \
        --dest=org.freedesktop.secrets \
        /org/freedesktop/secrets \
        org.freedesktop.DBus.Peer.Ping \
        >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

cd /src
exec bash build.sh build_linux
N00B_DBUS_BUILD

    chmod +x /tmp/n00b-dbus-build.sh
    # NCC_PATH (exported above) + the N00B_* env are inherited by the session.
    exec dbus-run-session -- /tmp/n00b-dbus-build.sh
fi

cd /src
exec bash build.sh build_linux
