// Tiny shim so docker.ts can be tested without monkey-patching node:os.
import * as nodeOs from 'node:os';

export const os = {
  userInfo: () => nodeOs.userInfo(),
  cpus: () => nodeOs.cpus(),
};
