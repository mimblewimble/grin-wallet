/* Sample Code for connecting to the V3 Secure API via Node
 *
 * With thanks to xiaojay of Niffler Wallet:
 * https://github.com/grinfans/Niffler/blob/gw3/src/shared/walletv3.js
 *
 */

const jayson = require('jayson/promise');
const crypto = require('crypto');

const client = jayson.client.http('http://localhost:3420/v3/owner');

// Demo implementation of using `aes-256-gcm` with node.js's `crypto` lib.
const aes256gcm = (shared_secret) => {
	const ALGO = 'aes-256-gcm';

	// encrypt returns base64-encoded ciphertext
	const encrypt = (str, nonce) => {
		let key = Buffer.from(shared_secret, 'hex')
		const cipher = crypto.createCipheriv(ALGO, key, nonce)
		const enc = Buffer.concat([cipher.update(str, 'utf8'), cipher.final()])
		const tag = cipher.getAuthTag()
		return Buffer.concat([enc, tag]).toString('base64')
	};

	// decrypt decodes base64-encoded ciphertext into a utf8-encoded string
	const decrypt = (enc, nonce) => {
		//key,nonce is all buffer type; data is base64-encoded string
		let key = Buffer.from(shared_secret, 'hex')
		const data_ = Buffer.from(enc, 'base64')
		const decipher = crypto.createDecipheriv(ALGO, key, nonce)
		const len = data_.length
		const tag = data_.slice(len-16, len)
		const text = data_.slice(0, len-16)
		decipher.setAuthTag(tag)
		const dec = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');
		return dec
	};

	return {
		encrypt,
		decrypt,
	};
};

class JSONRequestEncrypted {
	constructor(id, method, params) {
		this.jsonrpc = '2.0'
		this.method = method
		this.id = id
		this.params = params
	}
	
	async send(key){
		const aesCipher = aes256gcm(key);
		const nonce = new Buffer.from(crypto.randomBytes(12));
		let enc = aesCipher.encrypt(JSON.stringify(this), nonce);
		console.log("Encrypted: " + enc)
		let params = {
			'nonce': nonce.toString('hex'),
			'body_enc': enc,
		}
		let response = await client.request('encrypted_request_v3', params);

		if (response.err) {
			throw response.err
		}

		const nonce2 = Buffer.from(response.result.Ok.nonce, 'hex');
		const data = Buffer.from(response.result.Ok.body_enc, 'base64');

		let dec = aesCipher.decrypt(data, nonce2)
		return dec
	}
}

async function initSecure() {
	let ecdh = crypto.createECDH('secp256k1')
	ecdh.generateKeys()
	let publicKey = ecdh.getPublicKey('hex', 'compressed')
	const params = {
		'ecdh_pubkey': publicKey
	}	
	let response = await client.request('init_secure_api', params);
	if (response.err) {
		throw response.err
	}

	return ecdh.computeSecret(response.result.Ok, 'hex', 'hex')
}

function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
	let shared_key = await initSecure();

	let response = await new JSONRequestEncrypted(1, 'open_wallet', {
		"name": null,
		"password": "",
	}).send(shared_key);

	let token = JSON.parse(response).result.Ok;

	let iterations = 1;

	for (i=0; i<iterations*2; i+=2)  {
		let info_response = await new JSONRequestEncrypted(i, 'retrieve_summary_info', {
			"token": token,
			"refresh_from_node": true,
			"minimum_confirmations": 1,
		}).send(shared_key)

		console.log("Info Response: ", info_response);
		await sleep(2000)

		let txs_response = await new JSONRequestEncrypted(i+1, 'retrieve_txs', {
			"token": token,
			"refresh_from_node": true,
			"tx_id": null,
			"tx_slate_id": null,
		}).send(shared_key)

		console.log("Txs Response: ", txs_response);
		await sleep(2000)
	}
}



main();


