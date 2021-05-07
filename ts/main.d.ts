// Type definitions for @nuid/zk
// Project: @nuid/zk
// Definitions by: NuID Developers <https://portal.nuid.io/docs>

declare module "@nuid/zk" {

  // Bare types
  export type KnizkProtocol = "nuid.zk.protocol/knizk" 

  export type CurveFnSECP256K1 = "nuid.elliptic.curve/secp256k1"

  export type StringNormalizationNFKC = "string.normalization/NFKC"

  export type HashAlgorithmSHA256 = "nuid.cryptography.hash.algorithm/sha256"
  export type HashAlgorithmScrypt = "nuid.cryptography.hash.algorithm/scrypt"

  // Unions
  export type Protocol = KnizkProtocol
  export type CurveFn = CurveFnSECP256K1
  export type StringNormalization = StringNormalizationNFKC
  export type HashAlgorithm =
    HashAlgorithmSHA256
    | HashAlgorithmScrypt

  // Interfaces
  export interface Credential {
    "nuid.cryptography.hash/algorithm": HashAlgorithmScrypt,
    "nuid.cryptography.base64/salt": string,
    "string.normalization/form": StringNormalizationNFKC,
    "nuid.cryptography.hash.algorithm.scrypt/N": number,
    "nuid.cryptography.hash.algorithm.scrypt/r": number,
    "nuid.cryptography.hash.algorithm.scrypt/p": number,
    "nuid.cryptography.hash.algorithm.scrypt/length": number,
    "nuid.elliptic.curve/parameters": {
      "nuid.elliptic.curve/id": CurveFnSECP256K1
    },
    "nuid.elliptic.curve/point": string
  }

  export interface KnizkCredential {
    "nuid.zk/protocol": KnizkProtocol,
    "nuid.zk.knizk/curve": {
      "nuid.elliptic.curve/id": CurveFnSECP256K1
    },
    "nuid.zk.knizk/hashfn": {
      "string.normalization/form": StringNormalizationNFKC,
      "nuid.cryptography.hash/algorithm": HashAlgorithmSHA256
    },
    "nuid.zk.knizk/keyfn": {
      "nuid.cryptography.hash/algorithm": HashAlgorithmScrypt,
      "nuid.cryptography.base64/salt": string,
      "string.normalization/form": StringNormalizationNFKC,
      "nuid.cryptography.hash.algorithm.scrypt/N": number,
      "nuid.cryptography.hash.algorithm.scrypt/r": number,
      "nuid.cryptography.hash.algorithm.scrypt/p": number,
      "nuid.cryptography.hash.algorithm.scrypt/length": number
    },
    "nuid.zk.knizk/nonce": string,
    "nuid.zk.knizk/pub": {
      "nuid.elliptic.curve/parameters": {
        "nuid.elliptic.curve/id": CurveFnSECP256K1
      },
      "nuid.elliptic.curve/point": string
    },
    "nuid.zk.knizk/c": string,
    "nuid.zk.knizk/s": string
  }

  export interface KnizkChallenge {
    "nuid.zk/protocol": KnizkProtocol,
    "nuid.zk.knizk/curve": {
      "nuid.elliptic.curve/id": CurveFnSECP256K1
    },
    "nuid.zk.knizk/hashfn": {
      "string.normalization/form": StringNormalizationNFKC,
      "nuid.cryptography.hash/algorithm": HashAlgorithmSHA256
    },
    "nuid.zk.knizk/keyfn": {
      "nuid.cryptography.hash/algorithm": HashAlgorithmScrypt,
      "nuid.cryptography.base64/salt": string,
      "string.normalization/form": StringNormalizationNFKC,
      "nuid.cryptography.hash.algorithm.scrypt/N": number,
      "nuid.cryptography.hash.algorithm.scrypt/r": number,
      "nuid.cryptography.hash.algorithm.scrypt/p": number,
      "nuid.cryptography.hash.algorithm.scrypt/length": number
    },
    "nuid.zk.knizk/nonce": string,
    "nuid.zk.knizk/pub": {
      "nuid.elliptic.curve/parameters": {
        "nuid.elliptic.curve/id": CurveFnSECP256K1
      },
      "nuid.elliptic.curve/point": string
    }
  }

  export interface KnizkProof {
    "nuid.zk/protocol": KnizkProtocol,
    "nuid.zk.knizk/c": string,
    "nuid.zk.knizk/s": string
  }

  // Primary Unions
  export type VerifiedCredential = KnizkCredential
  export type Challenge = KnizkChallenge
  export type Proof = KnizkProof
  
  // Functions
  export function verifiableFromSecret(secret: string): VerifiedCredential;
  export function isVerified(verifiedCredential: VerifiedCredential): boolean;
  export function credentialFromVerifiable(verifiedCredential: VerifiedCredential): Credential;
  export function defaultChallengeFromCredential(credential: Credential): Challenge;
  export function proofFromSecretAndChallenge(secret: string, challenge: Challenge): Proof;
  export function verifiableFromProofAndChallenge(proof: Proof, challenge: Challenge): VerifiedCredential;
}
