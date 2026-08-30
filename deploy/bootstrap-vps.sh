#!/usr/bin/env bash
# A executer UNE FOIS sur le VPS (en root) : ssh vps-bernotti puis coller ce script,
# ou: scp deploy/bootstrap-vps.sh vps-bernotti:/root/ && ssh vps-bernotti bash /root/bootstrap-vps.sh
set -euo pipefail

APP_DIR=/opt/check-trade
REPO_URL=https://github.com/bbenjamin11/check-trade.git

echo ">>> Paquets de base"
apt-get update
apt-get install -y ca-certificates curl gnupg git nginx openssl

echo ">>> Installation Docker (repo officiel)"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

echo ">>> Clone du repo"
mkdir -p "$APP_DIR"
if [ -d "$APP_DIR/.git" ]; then
  echo "Repo deja present, pull au lieu de clone."
  git -C "$APP_DIR" pull
else
  git clone "$REPO_URL" "$APP_DIR"
fi
cd "$APP_DIR"

echo ">>> Fichier .env de production"
if [ ! -f .env ]; then
  echo "FLASK_SECRET_KEY=$(openssl rand -hex 32)" > .env
  echo ".env cree avec une nouvelle cle secrete (gardee uniquement sur le VPS)."
else
  echo ".env deja present, on ne le touche pas."
fi

echo ">>> Cle SSH dediee au deploiement GitHub Actions"
mkdir -p ~/.ssh && chmod 700 ~/.ssh
if [ ! -f ~/.ssh/deploy_check_trade ]; then
  ssh-keygen -t ed25519 -f ~/.ssh/deploy_check_trade -N "" -C "github-actions-deploy"
  cat ~/.ssh/deploy_check_trade.pub >> ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys
  echo ""
  echo "=================================================================="
  echo "CLE PRIVEE A COPIER TELLE QUELLE DANS LE SECRET GITHUB 'VPS_SSH_KEY'"
  echo "=================================================================="
  cat ~/.ssh/deploy_check_trade
  echo "=================================================================="
else
  echo "Cle de deploiement deja generee (~/.ssh/deploy_check_trade)."
fi

echo ">>> Nginx (reverse proxy port 80 -> conteneur 5000)"
cp "$APP_DIR/deploy/nginx-check-trade.conf" /etc/nginx/sites-available/check-trade
ln -sf /etc/nginx/sites-available/check-trade /etc/nginx/sites-enabled/check-trade
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo ">>> Dossier de logs"
mkdir -p "$APP_DIR/logs"

echo ">>> Premier build + lancement du conteneur"
docker compose up -d --build

echo ""
echo "Bootstrap termine. Verifie: curl http://127.0.0.1 (depuis le VPS) ou http://85.215.160.60 (depuis ton PC)."
