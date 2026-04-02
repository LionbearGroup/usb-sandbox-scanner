#!/usr/bin/env bash
# =============================================================================
# install.sh — Instalador do USB Sandbox Scanner
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERRO]${NC} $*"; exit 1; }
step()    { echo -e "\n${BOLD}▶ $*${NC}"; }

# --- Verifica root ---
[ "$EUID" -ne 0 ] && error "Execute como root: sudo ./install.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${BOLD}"
cat <<'BANNER'
  ██╗   ██╗███████╗██████╗      ███████╗ █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██╗  ██╗
  ██║   ██║██╔════╝██╔══██╗     ██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝
  ██║   ██║███████╗██████╔╝     ███████╗███████║██╔██╗ ██║██║  ██║██████╔╝██║   ██║ ╚███╔╝ 
  ██║   ██║╚════██║██╔══██╗     ╚════██║██╔══██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║ ██╔██╗ 
  ╚██████╔╝███████║██████╔╝     ███████║██║  ██║██║ ╚████║██████╔╝██████╔╝╚██████╔╝██╔╝ ██╗
   ╚═════╝ ╚══════╝╚═════╝      ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
BANNER
echo -e "${NC}"
echo -e "  ${CYAN}Kernel-level USB Malware Scanner${NC} — Instalador\n"

# =============================================================================
# PASSO 1: Dependências
# =============================================================================
step "Instalando dependências..."

apt-get update -qq
apt-get install -y -qq \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    util-linux \
    libnotify-bin \
    curl \
    2>/dev/null && success "Pacotes instalados (ClamAV, util-linux, libnotify)"

# =============================================================================
# PASSO 2: Atualizar banco de assinaturas
# =============================================================================
step "Atualizando banco de assinaturas ClamAV..."

systemctl stop clamav-freshclam 2>/dev/null || true
freshclam && success "Banco de assinaturas atualizado"
systemctl start clamav-freshclam 2>/dev/null || true

# =============================================================================
# PASSO 3: Instalar script principal
# =============================================================================
step "Instalando script principal..."

cp "$SCRIPT_DIR/usb-sandbox-scan.sh" /usr/local/bin/usb-sandbox-scan.sh
chmod 755 /usr/local/bin/usb-sandbox-scan.sh
success "Script instalado em /usr/local/bin/usb-sandbox-scan.sh"

# =============================================================================
# PASSO 4: Criar ponto de montagem isolado
# =============================================================================
step "Criando diretórios necessários..."

mkdir -p /mnt/usb-sandbox
chmod 700 /mnt/usb-sandbox

mkdir -p /var/log/usb-sandbox/reports
chmod 755 /var/log/usb-sandbox

success "Diretórios criados"

# =============================================================================
# PASSO 5: Instalar udev rule
# =============================================================================
step "Instalando regra udev..."

cp "$SCRIPT_DIR/99-usb-sandbox.rules" /etc/udev/rules.d/99-usb-sandbox.rules
chmod 644 /etc/udev/rules.d/99-usb-sandbox.rules

udevadm control --reload-rules
udevadm trigger
success "Regra udev instalada e recarregada"

# =============================================================================
# PASSO 6: Instalar serviço systemd
# =============================================================================
step "Instalando serviço systemd..."

cp "$SCRIPT_DIR/usb-sandbox@.service" /etc/systemd/system/usb-sandbox@.service
chmod 644 /etc/systemd/system/usb-sandbox@.service

systemctl daemon-reload
success "Serviço systemd instalado"

# =============================================================================
# PASSO 7: VirusTotal (opcional)
# =============================================================================
step "Configuração opcional — VirusTotal API"
echo ""
echo -e "  Deseja configurar integração com VirusTotal? (análise multi-engine)"
echo -e "  ${CYAN}(Obtenha sua chave grátis em: https://virustotal.com)${NC}"
echo -ne "\n  Cole sua API key (ou Enter para pular): "
read -r vt_key

if [ -n "$vt_key" ]; then
    cat > /etc/usb-sandbox.env <<ENV
VIRUSTOTAL_API_KEY=$vt_key
ENV
    chmod 600 /etc/usb-sandbox.env

    # Adiciona ao serviço systemd
    sed -i '/\[Service\]/a EnvironmentFile=/etc/usb-sandbox.env' \
        /etc/systemd/system/usb-sandbox@.service
    systemctl daemon-reload
    success "VirusTotal configurado"
else
    warn "VirusTotal ignorado — pode configurar depois em /etc/usb-sandbox.env"
fi

# =============================================================================
# RESUMO
# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  ✅ Instalação concluída com sucesso!${NC}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Como funciona:${NC}"
echo -e "  1. Insira o pendrive → udev detecta automaticamente"
echo -e "  2. Script monta em namespace isolado (kernel-level)"
echo -e "  3. ClamAV escaneia todos os arquivos"
echo -e "  4. Notificação desktop + relatório HTML gerado"
echo ""
echo -e "  ${BOLD}Localização dos relatórios:${NC}"
echo -e "  ${CYAN}/var/log/usb-sandbox/reports/${NC}"
echo ""
echo -e "  ${BOLD}Teste manual:${NC}"
echo -e "  ${CYAN}sudo usb-sandbox-scan.sh sdb1${NC}"
echo ""
echo -e "  ${BOLD}Logs em tempo real:${NC}"
echo -e "  ${CYAN}journalctl -fu 'usb-sandbox@*'${NC}"
echo ""
