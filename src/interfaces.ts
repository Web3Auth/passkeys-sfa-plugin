import { type AuthUserInfo, type BUILD_ENV_TYPE } from "@web3auth/auth";
import { PLUGIN_EVENTS } from "@web3auth/base";
import type { Auth0UserInfo, TorusSubVerifierInfo } from "@web3auth/single-factor-auth";

export interface PasskeyServiceEndpoints {
  register: {
    options: string;
    verify: string;
  };
  authenticate: {
    options: string;
    verify: string;
  };
  crud: {
    list: string;
    delete: string;
  };
}

export interface PasskeyExtraVerifierParams extends Record<string, string> {
  signature: string; // LOGIN
  clientDataJSON: string; // LOGIN
  authenticatorData: string; // LOGIN
  publicKey: string; // REGISTER
  challenge: string; // LOGIN
  rpId: string; // LOGIN/REGISTER
  credId: string; // LOGIN/REGISTER
}

export interface LoginParams {
  verifier: string;
  verifierId: string;
  idToken: string;
  subVerifierInfoArray?: TorusSubVerifierInfo[];
  // offset in seconds
  serverTimeOffset?: number;
  fallbackUserInfo?: Partial<Auth0UserInfo>;
  extraVerifierParams: PasskeyExtraVerifierParams;
}

export interface MetadataInfo {
  privKey: string;
  userInfo: AuthUserInfo;
}

export interface RegisterPasskeyParams {
  /**
   * The passkey in the user device will be saved with this name.
   *
   * @defaultValue loginProvider|verifierId
   */
  username?: string;
  /**
   * This option, if set, restricts the type of authenticators that can be registered.
   *
   * @defaultValue undefined.
   */
  authenticatorAttachment?: AuthenticatorAttachment;
}

export interface IPasskeysPluginOptions {
  buildEnv?: BUILD_ENV_TYPE;
  /**
   * `rpID` should be your app domain.
   *
   * If your app is hosted on "your.app.xyz" the RPID can be "your.app.xyz" or "app.xyz".
   *
   * Be aware: if you create passkeys on "your.app.xyz", they won't be usable on other subdomains (e.g. "other.app.xyz").
   * So unless you have good reasons not to, use the top-level domain as the RPID.
   *
   * `rpID` will show up in the initial registration popup:
   *
   * @defaultValue tld
   */
  rpID?: string;
  /**
   * `rpName` doesn't show up in the popup so can be set to anything.
   *
   * We recommend setting it to the correctly capitalized name of your app,
   * in case browsers start showing it in their native UIs in the future.
   *
   * @defaultValue window.title || window.location.hostname
   */
  rpName?: string;
}

export interface ListPasskeyResponse {
  id: number;
  credential_id: string;
  browser: string;
  browser_version: string;
  transport: string;
  os: string;
  os_version: string;
  platform: string;
  provider_name: string;
  created_at: string;
  updated_at: string;
}

export type PluginEvents = {
  [PLUGIN_EVENTS.READY]: () => void;
};
