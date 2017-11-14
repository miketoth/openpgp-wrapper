/**
 * Encrypts a message with pub/priv key. All messages are decrypted because thats easier to work with right now
 * TODO: make a wrapper funciton to speed test the encryption libs
 * */ 
const openpgp = require("openpgp");


// We can easily imagine a better function where an authenticated user only needs to supply the message and the users he/she wants to message. The system then iterates over their userObjects checking for public keys if they exist and creating a signed object for each one.
// We have the problem that an encrypted block is huge. Doing it on a per-field basis seems unreasonable. 
function betterEncryptFunction(message, publicKey, privateKey) {
  let encryptTime = process.hrtime();
  let passphrase = 'super long and hard to guess secret';
  let privKeyObj = openpgp.key.readArmored(privateKey).keys[0];
  privKeyObj.decrypt(passphrase);

  let options = {
    data: message,                             // input as String (or Uint8Array)
    publicKeys: openpgp.key.readArmored(publicKey).keys,  // for encryption
    privateKeys: privKeyObj // for signing (optional)
  }; 

  return openpgp.encrypt(options).then(function(ciphertext) {
      encryptTime = process.hrtime(encryptTime);
      console.log("benchmark %d seconds and %d nanoseconds", encryptTime[0], encryptTime[1]);
      return ciphertext.data; // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
  }); 

}

function decrypt(encrypted, publicKey, privateKey) {
    let passphrase = 'super long and hard to guess secret';
    let privKeyObj = openpgp.key.readArmored(privateKey).keys[0];
    privKeyObj.decrypt(passphrase);
    let options = { message: openpgp.message.readArmored(encrypted),     // parse armored message
      publicKeys: openpgp.key.readArmored(publicKey).keys,    // for verification (optional)
      privateKey: privKeyObj // for decryption
    };

    return openpgp.decrypt(options).then(function(plaintext) {
      return plaintext.data;
    });
}

module.exports = { betterEncryptFunction, decrypt };
