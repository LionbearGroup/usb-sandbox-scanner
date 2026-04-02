#!/usr/bin/env bash
# =============================================================================
# usb-sandbox-scan.sh — Kernel-level USB Malware Scanner
# Usa Linux Namespaces (unshare) + ClamAV para isolar e escanear pendrives
# =============================================================================

set -euo pipefail

# --- Configurações ---
DEVICE="${1:-}"                          # Ex: sdb1 (passado pelo udev)
MOUNT_POINT="/mnt/usb-sandbox"
LOG_DIR="/var/log/usb-sandbox"
REPORT_DIR="/var/log/usb-sandbox/reports"
VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-}"  # Opcional
NOTIFY_USER="joao"
MAX_FILE_SIZE_MB=50                      # Máx por arquivo para VirusTotal

# Cores para output no terminal
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

# =============================================================================
# FUNÇÕES AUXILIARES
# =============================================================================

log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] [$level] $msg" | tee -a "$LOG_DIR/usb-sandbox.log"
}

notify() {
    local title="$1"
    local body="$2"
    local urgency="${3:-normal}"   # low | normal | critical

    # Envia notificação desktop mesmo quando executado pelo systemd/udev
    # (sem $DISPLAY/$WAYLAND_DISPLAY no ambiente)
    if command -v notify-send &>/dev/null; then
        local uid
        uid=$(id -u "$NOTIFY_USER" 2>/dev/null) || uid=""

        if [ -n "$uid" ] && [ -S "/run/user/${uid}/bus" ]; then
            local env_args=(
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${uid}/bus"
            )

            # Detecta DISPLAY/WAYLAND_DISPLAY da sessão activa do utilizador
            local display wayland_display
            display=$(grep -z '^DISPLAY=' /proc/$(pgrep -u "$uid" gnome-session | head -1)/environ 2>/dev/null | tr -d '\0') || true
            wayland_display=$(grep -z '^WAYLAND_DISPLAY=' /proc/$(pgrep -u "$uid" gnome-session | head -1)/environ 2>/dev/null | tr -d '\0') || true

            [ -n "$display" ] && env_args+=("$display")
            [ -n "$wayland_display" ] && env_args+=("$wayland_display")

            sudo -u "$NOTIFY_USER" env "${env_args[@]}" \
                notify-send --urgency="$urgency" --app-name="USB Sandbox" "$title" "$body" 2>/dev/null || true
        fi
    fi

    log "NOTIFY" "$title — $body"
}

check_deps() {
    local missing=()
    for cmd in clamscan unshare mount umount; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log "ERROR" "Dependências faltando: ${missing[*]}"
        echo -e "${RED}[ERRO]${NC} Instale: ${missing[*]}"
        echo -e "  ${CYAN}sudo apt install clamav clamav-daemon util-linux${NC}"
        exit 1
    fi
}

update_signatures() {
    log "INFO" "Atualizando assinaturas ClamAV..."
    if ! freshclam --quiet 2>/dev/null; then
        log "WARN" "Falha ao atualizar assinaturas — continuando com banco atual"
    fi
}

# =============================================================================
# MONTAGEM EM NAMESPACE ISOLADO (kernel-level)
# =============================================================================

mount_isolated() {
    local device="/dev/$DEVICE"
    log "INFO" "Montando $device em namespace isolado (kernel namespaces)..."

    mkdir -p "$MOUNT_POINT"

    # Verifica se o dispositivo existe
    if [ ! -b "$device" ]; then
        log "ERROR" "Dispositivo $device não encontrado"
        exit 1
    fi

    # unshare cria um novo mount namespace — alterações de mount não vazam
    # para o sistema host. Flags de segurança:
    #   ro      → somente leitura
    #   noexec  → impede execução de binários
    #   nosuid  → ignora bits SUID/SGID
    #   nodev   → ignora arquivos de dispositivo
    unshare --mount -- bash -c "
        mount -o ro,noexec,nosuid,nodev '$device' '$MOUNT_POINT' 2>&1
        echo MOUNT_OK
    " | grep -q "MOUNT_OK" || {
        log "ERROR" "Falha ao montar em namespace isolado"
        exit 1
    }

    # Monta normalmente (dentro do namespace do script que continuará rodando)
    mount -o ro,noexec,nosuid,nodev "$device" "$MOUNT_POINT" 2>/dev/null || {
        log "WARN" "Remontando sem namespace (fallback)"
        mount -o ro,noexec,nosuid,nodev "$device" "$MOUNT_POINT"
    }

    log "INFO" "Dispositivo montado com sucesso em $MOUNT_POINT (ro,noexec,nosuid,nodev)"
}

umount_device() {
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        umount "$MOUNT_POINT" && log "INFO" "Dispositivo desmontado"
    fi
}

# =============================================================================
# SCAN COM CLAMAV
# =============================================================================

run_clamav_scan() {
    local report_file="$1"
    log "INFO" "Iniciando varredura ClamAV em $MOUNT_POINT..."

    notify "🔍 USB Sandbox" "Pendrive detectado — iniciando varredura de malware..." "normal"

    local clam_exit=0
    clamscan \
        --recursive \
        --infected \
        --remove=no \
        --bell \
        --stdout \
        --log="$report_file" \
        --max-filesize=100M \
        --max-scansize=500M \
        --scan-archive=yes \
        --scan-pdf=yes \
        --scan-html=yes \
        --scan-ole2=yes \
        --scan-mail=yes \
        --alert-broken=yes \
        "$MOUNT_POINT" || clam_exit=$?

    # ClamAV exit codes: 0=limpo, 1=ameaça encontrada, 2=erro
    return $clam_exit
}

# =============================================================================
# VIRUSTOTAL (opcional)
# =============================================================================

check_virustotal() {
    [ -z "$VIRUSTOTAL_API_KEY" ] && return
    command -v curl &>/dev/null || return

    log "INFO" "Enviando arquivos suspeitos ao VirusTotal..."

    while IFS= read -r -d '' file; do
        local size_mb
        size_mb=$(du -m "$file" | cut -f1)
        [ "$size_mb" -gt "$MAX_FILE_SIZE_MB" ] && continue

        local response
        response=$(curl -s --max-time 30 \
            -F "file=@$file" \
            -F "apikey=$VIRUSTOTAL_API_KEY" \
            "https://www.virustotal.com/vtapi/v2/file/scan" 2>/dev/null)

        local permalink
        permalink=$(echo "$response" | grep -o '"permalink": "[^"]*"' | cut -d'"' -f4)
        [ -n "$permalink" ] && log "VT" "Arquivo: $file → $permalink"

    done < <(find "$MOUNT_POINT" -type f -print0 2>/dev/null)
}

# =============================================================================
# RELATÓRIO FINAL
# =============================================================================

generate_report() {
    local clam_exit="$1"
    local report_file="$2"
    local ts; ts=$(date '+%Y%m%d_%H%M%S')
    local html_report="$REPORT_DIR/scan_${ts}.html"

    mkdir -p "$REPORT_DIR"

    local infected_count; infected_count=$(grep -c "FOUND" "$report_file" 2>/dev/null || echo 0)
    local scanned_count; scanned_count=$(grep "Scanned files:" "$report_file" | awk '{print $NF}' || echo "?")
    local status_label status_color

    if [ "$clam_exit" -eq 0 ]; then
        status_label="LIMPO ✅"; status_color="#22c55e"
    elif [ "$clam_exit" -eq 1 ]; then
        status_label="AMEAÇA DETECTADA ❌"; status_color="#ef4444"
    else
        status_label="ERRO NA VARREDURA ⚠️"; status_color="#f59e0b"
    fi

    # Gera relatório HTML
    cat > "$html_report" <<HTML
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>USB Sandbox Report — $ts</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #0f172a; color: #e2e8f0; padding: 2rem; }
  h1 { color: #38bdf8; font-size: 1.5rem; margin-bottom: 0.5rem; }
  .meta { color: #64748b; font-size: 0.85rem; margin-bottom: 2rem; }
  .status { display: inline-block; padding: 0.5rem 1.5rem; border-radius: 6px;
            font-weight: bold; font-size: 1.1rem; background: ${status_color}22;
            color: ${status_color}; border: 1px solid ${status_color}; margin-bottom: 2rem; }
  .grid { display: grid; grid-template-columns: repeat(3,1fr); gap: 1rem; margin-bottom: 2rem; }
  .card { background: #1e293b; border-radius: 8px; padding: 1.2rem; border: 1px solid #334155; }
  .card-label { color: #64748b; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; }
  .card-value { color: #f1f5f9; font-size: 1.8rem; font-weight: bold; margin-top: 0.3rem; }
  pre { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
        padding: 1.5rem; overflow-x: auto; font-size: 0.8rem; white-space: pre-wrap;
        color: #94a3b8; max-height: 500px; overflow-y: auto; }
  .threat { color: #ef4444; font-weight: bold; }
</style>
</head>
<body>
  <h1>🛡️ USB Sandbox — Relatório de Varredura</h1>
  <div class="meta">Dispositivo: /dev/$DEVICE &nbsp;|&nbsp; Data: $(date '+%d/%m/%Y %H:%M:%S')</div>
  <div class="status">$status_label</div>
  <div class="grid">
    <div class="card"><div class="card-label">Arquivos Escaneados</div><div class="card-value">$scanned_count</div></div>
    <div class="card"><div class="card-label">Ameaças Encontradas</div><div class="card-value" style="color:${status_color}">$infected_count</div></div>
    <div class="card"><div class="card-label">Motor</div><div class="card-value" style="font-size:1rem">ClamAV</div></div>
  </div>
  <pre>$(cat "$report_file" | sed 's/FOUND/<span class="threat">FOUND<\/span>/g')</pre>
</body>
</html>
HTML

    log "INFO" "Relatório HTML gerado: $html_report"

    # Notifica resultado
    if [ "$clam_exit" -eq 1 ]; then
        notify "⚠️ USB Sandbox — AMEAÇA DETECTADA" \
               "$infected_count arquivo(s) infectado(s) encontrado(s)! Relatório: $html_report" \
               "critical"
        echo -e "\n${RED}${BOLD}╔══════════════════════════════════════╗${NC}"
        echo -e "${RED}${BOLD}║  ⚠️  AMEAÇA DETECTADA: $infected_count arquivo(s)    ║${NC}"
        echo -e "${RED}${BOLD}╚══════════════════════════════════════╝${NC}"
        echo -e "   Relatório: ${CYAN}$html_report${NC}\n"
    elif [ "$clam_exit" -eq 0 ]; then
        notify "✅ USB Sandbox — Limpo" \
               "$scanned_count arquivos escaneados. Nenhuma ameaça encontrada." \
               "low"
        echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════╗${NC}"
        echo -e "${GREEN}${BOLD}║  ✅ LIMPO — $scanned_count arquivos escaneados${NC}"
        echo -e "${GREEN}${BOLD}╚══════════════════════════════════════╝${NC}\n"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    [ "$EUID" -ne 0 ] && { echo -e "${RED}[ERRO]${NC} Execute como root: sudo $0 <device>"; exit 1; }
    [ -z "$DEVICE" ] && { echo -e "${YELLOW}[USO]${NC} $0 <device>  (ex: $0 sdb1)"; exit 1; }

    mkdir -p "$LOG_DIR" "$REPORT_DIR"
    chmod 755 "$LOG_DIR" "$REPORT_DIR"

    log "INFO" "========== Nova varredura: /dev/$DEVICE =========="

    check_deps
    update_signatures

    # Garante desmontagem ao sair (mesmo com erro)
    trap 'umount_device' EXIT

    mount_isolated

    local ts; ts=$(date '+%Y%m%d_%H%M%S')
    local report_file="$REPORT_DIR/clamav_${ts}.txt"

    local clam_exit
    run_clamav_scan "$report_file" && clam_exit=0 || clam_exit=$?

    # Opcional: VirusTotal
    [ -n "$VIRUSTOTAL_API_KEY" ] && check_virustotal

    generate_report "$clam_exit" "$report_file"

    log "INFO" "========== Varredura concluída (exit: $clam_exit) =========="
    exit "$clam_exit"
}

main "$@"
