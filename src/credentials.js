var Bip39 = require('bip39'),
    Ecrypt = require('melis-ecrypt'),
    randomBytes = require('randombytes');


function Credentials (versions) {
  if (!(this instanceof Credentials)) return new Credentials()

  this.SCRYPT_PARAMS = {
    N: 1024,
    r: 4,
    p: 8
  }

  this.SEED_SIZE = 64
  this.ENTROPY_SIZE = 32

  this.wordlists = {
    en: Bip39.wordlists.english,
    it: Bip39.wordlists.italian
  }

}


Credentials.prototype.initializeGenerator = function(bytes) {
  var generator;
  bytes || (bytes = this.ENTROPY_SIZE);
  generator = randomBytes(bytes).toString('hex');
  return generator;
}


Credentials.prototype.validateMnemonic = function(mnemonic, language) {
  var list, res;
  if (language) {
    list = this.wordListFor(language);
  } else {
    res = this.inferWordList(mnemonic);
    language = res.language;
    list = res.list;
  }
  return {
    language: language,
    valid: Bip39.validateMnemonic(mnemonic, list)
  };
}

Credentials.prototype.isMnemonicValid = function(mnemonic) {
  return this.validateMnemonic(mnemonic).valid;
}

Credentials.prototype.isGeneratorValid = function(gen) {
  var buf;
  try {
    buf = new Buffer(gen, 'hex');
    return {
      valid: true,
      encrypted: buf.length === 40
    };
  } catch (e) {
    return false;
  }
}

Credentials.prototype.isGeneratorEncrypted = function(gen) {
  var res;
  return (res = this.isGeneratorValid(gen)) && res.encrypted;
}


Credentials.prototype.isMnemonicEncrypted = function(mnemonic) {
  return this.isGeneratorEncrypted(this.mnemonicToEntropy(mnemonic).entropy);
}


Credentials.prototype.importMnemonic = function(mnemonic, passphrase) {
  if (this.isMnemonicEncrypted(mnemonic)) {
    return this.decryptMnemonic(mnemonic, passphrase);
  } else {
    return this.mnemonicToEntropy(mnemonic);
  }
}

Credentials.prototype.generateMnemonic = function(entropy, language) {
  language || (language = 'en');
  return Bip39.entropyToMnemonic(entropy, this.wordListFor(language));
}

Credentials.prototype.mnemonicToEntropy = function(mnemonic) {
  var wordlist;
  wordlist = this.inferWordList(mnemonic);
  return {
    language: wordlist.language,
    entropy: Bip39.mnemonicToEntropy(mnemonic, wordlist.list)
  };
}

Credentials.prototype.entropyToSeed = function(entropy) {
  return Bip39.mnemonicToSeedHex(entropy).slice(0, this.SEED_SIZE);
}

Credentials.prototype.encryptGenerator = function(generator, key) {
  if (!key) throw new Error('key is mandatory');

  var data, ecrypt, salt;
  salt = randomBytes(8);
  ecrypt = new Ecrypt();
  ecrypt.scryptParams = this.SCRYPT_PARAMS;
  data = new Buffer(generator, 'hex');
  return ecrypt.encrypt(data, key, salt).toString('hex');
}

Credentials.prototype.decryptGenerator = function(data, key) {
  if (!key) throw new Error('key is mandatory');

  var ecrypt;
  ecrypt = new Ecrypt();
  ecrypt.scryptParams = this.SCRYPT_PARAMS;
  data = new Buffer(data, 'hex');
  return ecrypt.decrypt(data, key).secret.toString('hex');
}

Credentials.prototype.decryptMnemonic = function(data, key) {
  var res;
  res = this.mnemonicToEntropy(data);
  return {
    language: res.language,
    entropy: this.decryptGenerator(res.entropy, key)
  };
}

Credentials.prototype.parseMnemonics = function(mnemonic, passphrase) {
  var res = this.importMnemonic(mnemonic, passphrase);
  if(res.entropy) {
    res.seed = this.entropyToSeed(res.entropy);
    return res;
  }
}

Credentials.prototype.seedFromMnemonics = function(mnemonic, passphrase) {
  return this.parseMnemonics(mnemonic, passphrase).seed;
}

Credentials.prototype.wordListFor = function(language) {
  var list;
  language || (language = 'en');
  language = language.substring(0, 2).toLowerCase()
  list = this.wordlists[language];

  return list
}

Credentials.prototype.inferWordList = function(mnemonic) {
  var candidate, lang, list;
  if (!mnemonic) { return null; }

  candidate = mnemonic.substr(0, mnemonic.indexOf(' '));
  for (lang in this.wordlists) {
    list = this.wordlists[lang];
    if (list.includes(candidate)) {
      return { language: lang, list: list };
    }
  }
  return {
    language: 'en',
    list: this.wordlists.en
  };
}

module.exports = Credentials
