export interface AttestationReport {
  readonly provider: 'simulator' | 'dstack' | 'nitro';
  readonly timestamp: number;
  readonly measurements: CodeMeasurements;
  readonly userData: string;
  readonly signature: string;
}

export interface CodeMeasurements {
  /** Hash of the enclave code */
  readonly mrEnclave: string;
  /** Hash of the signer identity */
  readonly mrSigner: string;
  /** Product ID */
  readonly productId: number;
  /** Security version number */
  readonly svn: number;
}

export interface AttestationQuote {
  readonly report: AttestationReport;
  readonly nonce: string;
  readonly rootPublicKey: string;
}

export interface AttestationVerifyRequest {
  readonly quote: AttestationQuote;
  readonly expectedMeasurements?: Partial<CodeMeasurements>;
}

export interface AttestationVerifyResult {
  readonly valid: boolean;
  readonly reason?: string;
  readonly report?: AttestationReport;
}
