# Connecting to the wallet's V3 Owner API from Node

This is a small sample with code that demonstrates how to initialize the Wallet V3's Secure API and call API functions through it.

To run this sample:

First run the Owner API:

```.sh
grin-wallet owner_api
```

This sample doesn't use the authentication specified in the wallet's `.api_secret`, so before running the owner_api please ensure api authentication is commented out in `grin-wallet.toml`. Including the authentication token as part of the request is a function of your json-rpc client library of choice, so it's not included in the sample to make setup a bit simpler.

ensure the client url in `src\index.js` is set correctly:

```.sh
const client = jayson.client.http('http://localhost:3420/v3/owner');
```

Then (assuming node.js and npm are installed on the system):

```.sh
npm install
node src/index.json
```

Feel free to play around with the sample, modifying it to call whatever functions you'd like to see in operation!
