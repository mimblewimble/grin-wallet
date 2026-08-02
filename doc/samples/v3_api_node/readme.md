# Connecting to the wallet's V3 Owner API from Node

This is a small sample with code that demonstrates how to initialize the Wallet V3's Secure API and call API functions through it.

To run this sample:

First run the Owner API:

```.sh
grin-wallet owner_api
```

The Owner API uses HTTP Basic authentication when `api_secret_path` is configured in `grin-wallet.toml`. Before running the sample, load the secret from that file into an environment variable:

```.sh
export GRIN_OWNER_API_SECRET="$(cat /path/to/.owner_api_secret)"
```

The sample sends it as the password for the `grin` user. If `api_secret_path` is disabled, the environment variable can be omitted.

Ensure the client connection settings in `src/index.js` match the Owner API address.

Then (assuming node.js and npm are installed on the system):

```.sh
npm install
node src/index.js
```

Feel free to play around with the sample, modifying it to call whatever functions you'd like to see in operation!
