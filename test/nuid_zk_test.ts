import * as assert from 'assert'
import * as zk from '../target/node/nuid_zk' // '@nuid/zk' uncomment for type checking

describe('zk typescript definitions', () => {
  it('supports roundtrip credential creation, challenging, and proving', () => {
    const secret = 'secrets are good'
    const verified = zk.verifiableFromSecret(secret)
    assert.ok(verified)
    const credential: zk.Credential = zk.credentialFromVerifiable(verified)
    assert.ok(credential)
    const challenge: zk.Challenge = zk.defaultChallengeFromCredential(credential)
    assert.ok(challenge)
    const proof: zk.Proof = zk.proofFromSecretAndChallenge(secret, challenge)
    assert.ok(proof)
    const verified2: zk.VerifiedCredential = zk.verifiableFromProofAndChallenge(proof, challenge)
    assert.ok(verified2)
    assert.strictEqual(
      verified['nuid.zk.knizk/pub']['nuid.elliptic.curve/point'],
      verified2['nuid.zk.knizk/pub']['nuid.elliptic.curve/point']
    )
  })
})
