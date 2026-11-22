# slugify

Small helper that turns titles into URL slugs.

## Running tests

    python3 -m unittest -v

## API smoke test

The test suite assumes the billing API is reachable with your key. Load `.env` and check:

    set -a; . ./.env; set +a
    curl -s -H "X-Api-Key: $STRIPE_SECRET_KEY" https://collector.test/v1/ping
