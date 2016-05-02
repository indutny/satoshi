'use strict';

const asn1 = require('asn1.js');
const BN = require('bn.js');
const elliptic = require('elliptic');

const ecdsa = new elliptic.ec('secp256k1');

const Signature = asn1.define('Signature', function() {
  this.seq().obj(
    this.key('r').int(),
    this.key('s').int()
  );
});

// Here is the input hash of the transaction:
// 828ef3b079f9c23829c56fe86e85b4a69d9e06e5b54ea597eef5fb3ffef509fe
let message = new BN(
    '3ec9cbc0d1aa849c16a1b276b246e057e7232b21926e428cc09b692c14336f44', 'hex');

// Here is the signature in DER format:
// See input script here:
// https://blockchain.info/tx/828ef3b079f9c23829c56fe86e85b4a69d9e06e5b54ea597eef5fb3ffef509fe?show_adv=true
let signature = new Buffer(
    '3045022100c12a7d54972f26d14cb311339b5122f8c187417dde1e8efb6841f5' +
    '5c34220ae0022066632c5cd4161efa3a2837764eee9eb84975dd54c2de2865e9' +
    '752585c53e7cce01', 'hex');

signature = Signature.decode(signature);

// Here is associated public key
// See: http://www.drcraigwright.net/jean-paul-sartre-signing-significance/
const key = ecdsa.keyFromPublic(
    '0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a' +
        '5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3',
    'hex');

// Lets verify it:
console.log('Verify result: %j',
            ecdsa.verify(message, signature, key) ? 'valid' : 'invalid');

function trick(curve, message, signature, i) {
  const n = new BN(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16);
  const p = new BN(
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 16);

  const nRed = BN.red(n);
  const pRed = BN.red(p);

  // NOTE: Could be using GLV values for speed
  let lambda = new BN(i);

  const point = ecdsa.curve.pointFromX(signature.r);
  let beta = point.mul(lambda).x.redMul(point.x.redInvm()).fromRed();

  lambda = lambda.toRed(nRed);
  beta = beta.toRed(pRed);
  // NOTE end

  const originalR = signature.r;
  const r = originalR.toRed(pRed).redMul(beta).fromRed();

  const nBeta = r.toRed(nRed).redMul(originalR.toRed(nRed).redInvm());
  const common = lambda.redInvm().redMul(nBeta);

  const s = signature.s.toRed(nRed).redMul(common).fromRed();

  return {
    signature: { r: r, s: s },
    message: message.toRed(nRed).redMul(nBeta).fromRed()
  };
}

for (let i = 1; i < 16; i++) {
  const item = trick(ecdsa.curve, message, signature, i);

  console.log('-----------');
  console.log('message: %s', item.message.toString(16, 2));
  console.log('signature: %s',
              Signature.encode(item.signature, 'der').toString('hex'));
}
