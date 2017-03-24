var assert = require('assert')
var Creds = require('../src/credentials')
var fixtures = require('./fixtures')


describe('credentials', function () {
  var creds
  beforeEach(function () {
    creds = new Creds()
  })


  describe('Generator', function () {
    it('should generate a defaul length generator', function () {
      var a = creds.initializeGenerator();
      console.log(a);
      assert.equal(a.length, 64);
    }),

    it('should generate a given length generator', function () {
      var a = creds.initializeGenerator(16);
      console.log(a);
      assert.equal(a.length, 32);
    })

  })


  describe('Validation', function() {
    it('should validate simple mnemonic', function () {
      ['en', 'it'].forEach(function(l) {
        var res = creds.validateMnemonic(fixtures.vecs.simple[l].text);
        console.log(res);
        assert.equal(res.language, l);
        assert.ok(res.valid);
      })
    })

    it('should validate encrypted mnemonic', function () {
      ['en', 'it'].forEach(function(l) {
        var res = creds.validateMnemonic(fixtures.vecs.encrypted[l].text);
        console.log(res);
        assert.equal(res.language, l);
        assert.ok(res.valid);
      })
    })

    it('should recognize invalid anemonic', function () {
      var vec;
      ['truncated', 'missing', 'bad_word'].forEach(function(i) {
        vec = fixtures.vecs.invalid[i];

        ['en', 'it'].forEach(function(l) {
          var res = creds.validateMnemonic(vec[l]);
          console.log(i, res);
          assert.equal(res.language, l);
          assert.equal(res.valid, false);
        })
      })
    })
  })


  describe('Encryption', function() {
    it('should detect encrypted mnemonics', function () {
      ['en', 'it'].forEach(function(l) {
        var text = fixtures.vecs.encrypted[l].text
        var res = creds.isMnemonicEncrypted(text);
        assert.equal(res, true);
      })
    })

    it('should not detect unencrypted mnemonics', function () {
      ['en', 'it'].forEach(function(l) {
        var text = fixtures.vecs.simple[l].text
        var res = creds.isMnemonicEncrypted(text);
        assert.equal(res, false);
      })
    })

  })

  describe('Plaintext Mnemonics', function () {
    it('should generate a seed from mnemonics', function () {
      ['en', 'it'].forEach(function(l) {
        var text = fixtures.vecs.simple[l].text
        var res = creds.parseMnemonics(text);
        console.log(res);
        assert.equal(res.language, l);
        assert.equal(res.entropy, fixtures.vecs.simple[l].entropy);
        assert.equal(res.seed, fixtures.vecs.simple[l].seed);
      })
    })

    it('should generate a seed from mnemonics, direct', function () {
      ['en', 'it'].forEach(function(l) {
        var text = fixtures.vecs.simple[l].text
        var seed = creds.seedFromMnemonics(text);
        console.log(seed);
        assert.equal(seed, fixtures.vecs.simple[l].seed);
      })
    })
  })

  describe('Encrypted Mnemonics', function () {
    it('should generate a seed from encrypted mnemonics', function () {
      ['en', 'it'].forEach(function(l) {
        var text = fixtures.vecs.encrypted[l].text
        assert.equal(creds.isMnemonicEncrypted(text), true);
        var res = creds.parseMnemonics(text, fixtures.vecs.encrypted[l].secret);
        console.log(res);
        assert.equal(res.language, l);
        assert.equal(res.entropy, fixtures.vecs.encrypted[l].entropy);
        assert.equal(res.seed, fixtures.vecs.encrypted[l].seed);
      })
    })

    it('should generate a seed from encrypted mnemonics, direct', function () {
      ['en', 'it'].forEach(function(l) {
        var text = fixtures.vecs.encrypted[l].text
        assert.equal(creds.isMnemonicEncrypted(text), true);
        var seed = creds.seedFromMnemonics(text, fixtures.vecs.encrypted[l].secret);
        console.log(seed);
        assert.equal(seed, fixtures.vecs.encrypted[l].seed);
      })
    })


    it('should NOT generate a seed from encrypted mnemonics if password is wrong', function () {
      ['en', 'it'].forEach(function(l) {
        var text = fixtures.vecs.encrypted[l].text
        assert.equal(creds.isMnemonicEncrypted(text), true);
        var res = creds.parseMnemonics(text, 'wrongpass');
        console.log(res);
        assert.equal(res.language, l);
        assert.notEqual(res.entropy, fixtures.vecs.encrypted[l].entropy);
        assert.notEqual(res.seed, fixtures.vecs.encrypted[l].seed);
      })
    })

    it('should NOT generate a seed from encrypted mnemonics if no secret', function () {
      ['en', 'it'].forEach(function(l) {
        var text = fixtures.vecs.encrypted[l].text
        assert.equal(creds.isMnemonicEncrypted(text), true);
        assert.throws(function() { creds.parseMnemonics(text) }, Error);
      })
    })
  })


})
