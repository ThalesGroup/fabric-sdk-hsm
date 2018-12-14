/*
 *  Copyright (C) 2018 SafeNet. All rights reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

const path = require('path');
const fs = require('fs-extra');
const util = require('util');

var jsrsa = require('jsrsasign');
var KEYUTIL = jsrsa.KEYUTIL;
var ecdsaKey = require('fabric-client/lib/impl/ecdsa/key.js');

const Client = require('fabric-client');
const copService = require('fabric-ca-client/lib/FabricCAServices.js');
const User = require('fabric-client/lib/User.js');
const Constants = require('./constants.js');

const logger = require('fabric-client/lib/utils.js').getLogger('TestUtil');

const tempdir = Constants.tempdir;

//const PKCS11_LIB = '/usr/safenet/lunaclient/lib/libCryptoki2_64.so';
const PKCS11_LIB = '/usr/safenet/lunaclient/lib/libcklog2.so';
const PKCS11_SLOT = 0;
const PKCS11_PIN = 'userpin';
const PKCS11_USER_TYPE = 1;

const CRYPTO_SUITE_OPTS = {software: false, lib: PKCS11_LIB, slot: PKCS11_SLOT, pin: PKCS11_PIN, user_type: PKCS11_USER_TYPE};

module.exports.KVS = path.join(tempdir, 'hfc-test-kvs');
module.exports.storePathForOrg = function(org) {
	return module.exports.KVS + '_' + org;
};

Client.addConfigFile(path.join(__dirname, '../integration/e2e/config.json'));
const ORGS = Client.getConfigSetting('test-network');

const tlsOptions = {
	trustedRoots: [],
	verify: false
};

function getMember(username, password, client, t, userOrg) {
	const caUrl = ORGS[userOrg].ca.url;

	const cryptoSuite = Client.newCryptoSuite(CRYPTO_SUITE_OPTS);
	if (client._stateStore) {
		cryptoSuite.setCryptoKeyStore(Client.newCryptoKeyStore({path: module.exports.storePathForOrg(ORGS[userOrg].name)}));
	}
	client.setCryptoSuite(cryptoSuite);

	return client.getUserContext(username, true)
		.then((user) => {
			// eslint-disable-next-line no-unused-vars
			return new Promise((resolve, reject) => {
				if (user && user.isEnrolled()) {
					t.pass('Successfully loaded member from persistence');
					return resolve(user);
				}

				const member = new User(username);
				member.setCryptoSuite(cryptoSuite);

				// need to enroll it with CA server
				const cop = new copService(caUrl, tlsOptions, ORGS[userOrg].ca.name, cryptoSuite);

				return cop.enroll({
					enrollmentID: username,
					enrollmentSecret: password
				}).then((enrollment) => {
					t.pass('Successfully enrolled user \'' + username + '\'');

					return member.setEnrollment(enrollment.key, enrollment.certificate, ORGS[userOrg].mspid);
				}).then(() => {
					let skipPersistence = false;
					if (!client.getStateStore()) {
						skipPersistence = true;
					}
					return client.setUserContext(member, skipPersistence);
				}).then(() => {
					return resolve(member);
				}).catch((err) => {
					t.fail('Failed to enroll and persist user. Error: ' + err.stack ? err.stack : err);
					t.end();
				});
			});
		});
}

module.exports.setAdmin = function(client, userOrg) {
	return getAdmin(client, null, userOrg);
};

async function getAdmin(client, t, userOrg) {

	const certPath = path.join(__dirname, util.format('../fixtures/channel/crypto-config/peerOrganizations/%s.example.com/users/Admin@%s.example.com/signcerts', userOrg, userOrg));
	const certPEM = readAllFiles(certPath)[0];

	const cryptoSuite = Client.newCryptoSuite(CRYPTO_SUITE_OPTS);
	client.setCryptoSuite(cryptoSuite);

	const key = KEYUTIL.getKey(certPEM.toString());
	const key2 = new ecdsaKey(key);
	const privateKeyObj = await cryptoSuite.getKey(Buffer.from(key2.getSKI(), 'hex'));

	return Promise.resolve(client.createUser({
		username: 'peer' + userOrg + 'Admin',
		mspid: ORGS[userOrg].mspid,
		cryptoContent: {
			privateKeyObj: privateKeyObj,
			signedCertPEM: certPEM.toString()
		}
	}));
}

async function getOrdererAdmin(client, t) {
	const certPath = path.join(__dirname, '../fixtures/channel/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/signcerts');
	const certPEM = readAllFiles(certPath)[0];
	t.comment('getOrdererAdmin');

	const cryptoSuite = Client.newCryptoSuite(CRYPTO_SUITE_OPTS);
	client.setCryptoSuite(cryptoSuite);

	const key = KEYUTIL.getKey(certPEM.toString());
	const key2 = new ecdsaKey(key);
	const privateKeyObj = await cryptoSuite.getKey(Buffer.from(key2.getSKI(), 'hex'));

	return Promise.resolve(client.createUser({
		username: 'ordererAdmin',
		mspid: 'OrdererMSP',
		cryptoContent: {
			privateKeyObj: privateKeyObj,
			signedCertPEM: certPEM.toString()
		}
	}));
}

function readAllFiles(dir) {
	const files = fs.readdirSync(dir);
	const certs = [];
	files.forEach((file_name) => {
		const file_path = path.join(dir, file_name);
		logger.debug(' looking at file ::' + file_path);
		const data = fs.readFileSync(file_path);
		certs.push(data);
	});
	return certs;
}

module.exports.getOrderAdminSubmitter = function(client, test) {
	return getOrdererAdmin(client, test);
};

module.exports.getSubmitter = function(client, test, peerOrgAdmin, org) {
	if (arguments.length < 2) {
		throw new Error('"client" and "test" are both required parameters');
	}

	let peerAdmin, userOrg;
	if (typeof peerOrgAdmin === 'boolean') {
		peerAdmin = peerOrgAdmin;
	} else {
		peerAdmin = false;
	}

	// if the 3rd argument was skipped
	if (typeof peerOrgAdmin === 'string') {
		userOrg = peerOrgAdmin;
	} else {
		if (typeof org === 'string') {
			userOrg = org;
		} else {
			userOrg = 'org1';
		}
	}

	if (peerAdmin) {
		return getAdmin(client, test, userOrg);
	} else {
		return getMember('admin', 'adminpw', client, test, userOrg);
	}
};
