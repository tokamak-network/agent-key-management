export interface SignTransactionRequest {
  readonly keyId: string;
  readonly callerId: string;
  readonly transaction: TransactionData;
}

export interface TransactionData {
  readonly to: string;
  readonly value?: string;
  readonly data?: string;
  readonly nonce?: number;
  readonly gasLimit?: string;
  readonly maxFeePerGas?: string;
  readonly maxPriorityFeePerGas?: string;
  readonly chainId: number;
}

export interface SignedTransactionResult {
  readonly signedTransaction: string;
  readonly hash: string;
  readonly from: string;
}

export interface SignMessageRequest {
  readonly keyId: string;
  readonly callerId: string;
  readonly message: string;
}

export interface SignedMessageResult {
  readonly signature: string;
  readonly address: string;
}
