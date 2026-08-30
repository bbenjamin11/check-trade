#!/usr/bin/env bash
# HTTPS via Let's Encrypt (Certbot + plugin nginx) sur le VPS, en root.
#
# Usage : bash setup-https.sh <domaine> [email]
#   ex :  bash setup-https.sh benjamin.duckdns.org moi@example.com
#
# Le plugin nginx de Certbot modifie automatiquement la conf nginx
# (ajoute le bloc HTTPS + redirection 80->443) et programme le
# renouvellement automatique (timer systemd "certbot.timer", deja
# active par le paquet Debian).
set -euo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-}"

if [ -z "$DOMAIN" ]; then
  echo "Usage: bash setup-https.sh <domaine> [email]"
  exit 1
fi

APP_DIR=/opt/check-trade
NGINX_SITE=/etc/nginx/sites-available/check-trade

echo ">>> Verification DNS : $DOMAIN doit pointer vers l'IP de ce VPS"
RESOLVED=$(getent hosts "$DOMAIN" | awk '{print $1}' || true)
PUBLIC_IP=$(curl -s https://api.ipify.org || true)
echo "    $DOMAIN -> $RESOLVED"
echo "    IP publique de ce VPS -> $PUBLIC_IP"
if [ -n "$RESOLVED" ] && [ -n "$PUBLIC_IP" ] && [ "$RESOLVED" != "$PUBLIC_IP" ]; then
  echo "ATTENTION : le domaine ne semble PAS pointer vers ce VPS. Verifie DuckDNS avant de continuer."
  echo "Continuer quand meme dans 5s (Ctrl+C pour annuler)..."
  sleep 5
fi

echo ">>> Mise a jour du server_name dans la conf nginx"
sed -i "s/server_name _;/server_name ${DOMAIN};/" "$APP_DIR/deploy/nginx-check-trade.conf"
cp "$APP_DIR/deploy/nginx-check-trade.conf" "$NGINX_SITE"
nginx -t && systemctl reload nginx

echo ">>> Installation Certbot (plugin nginx)"
apt-get update
apt-get install -y certbot python3-certbot-nginx

echo ">>> Obtention du certificat + configuration HTTPS automatique"
CERTBOT_ARGS=(--nginx -d "$DOMAIN" --redirect --non-interactive --agree-tos)
if [ -n "$EMAIL" ]; then
  CERTBOT_ARGS+=(-m "$EMAIL")
else
  CERTBOT_ARGS+=(--register-unsafely-without-email)
fi
certbot "${CERTBOT_ARGS[@]}"

echo ">>> Renouvellement automatique (test a blanc, ne change rien)"
certbot renew --dry-run

echo ""
echo "Termine. Site accessible en HTTPS : https://${DOMAIN}"
echo "Le renouvellement est automatique (systemctl status certbot.timer pour verifier)."
