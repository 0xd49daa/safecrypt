export type {
  CryptoWorkerAPI,
  EncryptFileRequest,
  EncryptFileResponse,
  DecryptFileRequest,
  DecryptFileResponse,
  WrapKeySealRequest,
  WrapKeySealResponse,
  WrapKeyAuthenticatedRequest,
  WrapKeyAuthenticatedResponse,
  DeriveKeysRequest,
  DeriveKeysResponse,
} from './types.ts';

export { workerAPI } from './crypto.worker.ts';

export const WORKER_FILE_SIZE_THRESHOLD = 10 * 1024 * 1024;

export function shouldUseWorker(fileSize: number): boolean {
  return fileSize > WORKER_FILE_SIZE_THRESHOLD;
}
