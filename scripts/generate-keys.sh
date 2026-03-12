
set -euo pipefail

WRITE_ENV=false
ENV_FILE=".env"

for arg in "$@"; do
  case $arg in
    --write-env) WRITE_ENV=true ;;
  esac
done

echo ""
echo "=== Generating 2048-bit RSA key pair ==="
echo ""

# Generate private key
PRIVATE_PEM=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)

# Derive public key
PUBLIC_PEM=$(echo "$PRIVATE_PEM" | openssl rsa -pubout 2>/dev/null)

# Convert private key to base64 DER
RSA_PRIVATE_KEY=$(echo "$PRIVATE_PEM" \
  | openssl pkcs8 -topk8 -nocrypt -outform DER 2>/dev/null \
  | base64 | tr -d '\n')

# Convert public key to base64 DER
RSA_PUBLIC_KEY=$(echo "$PUBLIC_PEM" \
  | openssl rsa -pubin -outform DER 2>/dev/null \
  | base64 | tr -d '\n')

# Always print to terminal
echo "RSA_PRIVATE_KEY=${RSA_PRIVATE_KEY}"
echo ""
echo "RSA_PUBLIC_KEY=${RSA_PUBLIC_KEY}"
echo ""

# Write to .env if --write-env flag was passed
if [ "$WRITE_ENV" = true ]; then
  if [ -f "$ENV_FILE" ]; then
    grep -v "^RSA_PRIVATE_KEY=" "$ENV_FILE" \
      | grep -v "^RSA_PUBLIC_KEY=" > "${ENV_FILE}.tmp" || true
    mv "${ENV_FILE}.tmp" "$ENV_FILE"
  fi

  {
    echo "RSA_PRIVATE_KEY=${RSA_PRIVATE_KEY}"
    echo "RSA_PUBLIC_KEY=${RSA_PUBLIC_KEY}"
  } >> "$ENV_FILE"

  echo "Keys written to ${ENV_FILE}"
fi

echo ""
echo "Done. Next: run the app with ./mvnw spring-boot:run"
echo ""