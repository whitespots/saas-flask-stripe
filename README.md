# Install

1. `sqlite3 database.db < schema.sql`
2. Create the project https://console.developers.google.com/cloud-resource-manager
3. Create the key https://console.developers.google.com/apis/credentials
4. Configure whitelists of your js sources and redirects
5. Add products https://dashboard.stripe.com/test/products
6. Copy the Price ID to `settings.config['STRIPE_PRICE_ID']`
7. Add webhooks https://dashboard.stripe.com/test/webhooks with checkout events
8. You can use the stripe cli to get the webhook signing secret
9. **Change the ssl certificates** from testing to yours

Example

```buildoutcfg
https://localhost:5000/stripe_webhook
```
