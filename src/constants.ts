import { BUILD_ENV, type BUILD_ENV_TYPE, WEB3AUTH_NETWORK, type WEB3AUTH_NETWORK_TYPE } from "@web3auth/auth";

export const PASSKEY_SVC_URL: Record<BUILD_ENV_TYPE, string> = {
  [BUILD_ENV.DEVELOPMENT]: "http://localhost:3041",
  [BUILD_ENV.TESTING]: "https://api-develop-passwordless.web3auth.io",
  [BUILD_ENV.STAGING]: "https://api-passwordless.web3auth.io",
  [BUILD_ENV.PRODUCTION]: "https://api-passwordless.web3auth.io",
};

export const PASSKEYS_VERIFIER_MAP: Record<WEB3AUTH_NETWORK_TYPE, string> = {
  [WEB3AUTH_NETWORK.MAINNET]: "passkey-legacy-mainnet",
  [WEB3AUTH_NETWORK.TESTNET]: "passkey-legacy-testnet",
  [WEB3AUTH_NETWORK.AQUA]: "passkey-legacy-aqua",
  [WEB3AUTH_NETWORK.CYAN]: "passkey-legacy-cyan",
  [WEB3AUTH_NETWORK.SAPPHIRE_DEVNET]: "passkey-sapphire-devnet",
  [WEB3AUTH_NETWORK.SAPPHIRE_MAINNET]: "passkey-sapphire-mainnet",
  [WEB3AUTH_NETWORK.CELESTE]: "",
};
