
/**
 * Encrypts a message with pub/priv key. All messages are decrypted because thats easier to work with right now
 * */ 
var openpgp = require("openpgp");


// We can easily imagine a better function where an authenticated user only needs to supply the message and the users he/she wants to message. The system then iterates over their userObjects checking for public keys if they exist and creating a signed object for each one.
// We have the problem that an encrypted block is huge. Doing it on a per-field basis seems unreasonable. 
function betterEncryptFunction(message, publicKey, privateKey) {
  var passphrase = 'super long and hard to guess secret';
  var privKeyObj = openpgp.key.readArmored(privateKey).keys[0];
  privKeyObj.decrypt(passphrase);

  options = {
    data: message,                             // input as String (or Uint8Array)
    publicKeys: openpgp.key.readArmored(publicKey).keys,  // for encryption
    privateKeys: privKeyObj // for signing (optional)
  }; 

  return openpgp.encrypt(options).then(function(ciphertext) {
    var encrypted = ciphertext.data; // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'

    // BEGIN DECRYPT
    options = { message: openpgp.message.readArmored(encrypted),     // parse armored message
      publicKeys: openpgp.key.readArmored(publicKey).keys,    // for verification (optional)
      privateKey: privKeyObj // for decryption
    };

    return openpgp.decrypt(options).then(function(plaintext) {
      return plaintext.data; // 'Hello, World!'
    });
  }); 

}

module.exports = betterEncryptFunction;
