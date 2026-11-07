/** Shapes shared with the issuer and verifier services (see docs/credential-format.md). */
export interface Credential {
  type: 'ZKPG_INCOME_V1';
  issuer: { kid: string };
  claims: {
    subjectId: string;
    annualIncomeInr: string;
    issuedAt: string;
    expiresAt: string;
    credentialId: string;
  };
  signature: { alg: 'ES256'; value: string };
}

export interface IssuerInfo {
  name: string;
  kid: string;
  alg: 'ES256';
  jwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  circuit: { x: string; y: string };
}

export type RequestStatus = 'PENDING' | 'ELIGIBLE' | 'NOT_ELIGIBLE' | 'INVALID' | 'EXPIRED';

export interface ProofRequest {
  id: string;
  verifierName: string;
  minimumIncome: string;
  currentTime: string;
  challenge: string;
  createdAt: string;
  expiresAt: string; // unix seconds: respond before this
  status: RequestStatus;
  reason?: string;
  decidedAt?: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  event: string;
  requestId?: string;
  outcome?: string;
  reason?: string;
  issuerKid?: string;
  proofDigest?: string;
}

/** Exactly what is sent to the verifier. Nothing else leaves the device. */
export interface ProofSubmission {
  proof: string; // base64
  publicInputs: string[]; // 67 × 0x-prefixed 32-byte hex
}
