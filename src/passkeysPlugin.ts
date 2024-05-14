import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import { decryptData } from "@toruslabs/metadata-helpers";
import { SafeEventEmitter, SafeEventEmitterProvider } from "@toruslabs/openlogin-jrpc";
import { BUILD_ENV, OpenloginUserInfo } from "@toruslabs/openlogin-utils";
import Torus, { TorusPublicKey } from "@toruslabs/torus.js";
import { log, PLUGIN_EVENTS } from "@web3auth/base";
import { ADAPTER_EVENTS, IPlugin, type IWeb3Auth as ISFAWeb3auth } from "@web3auth/single-factor-auth";

import { PASSKEYS_VERIFIER_MAP } from "./constants";
import { IPasskeysPluginOptions, LoginParams, MetadataInfo, RegisterPasskeyParams } from "./interfaces";
import PasskeyService from "./passkeysSvc";
import { encryptData, getPasskeyVerifierId, getSiteName, getTopLevelDomain, getUserName } from "./utils";

export class PasskeysPlugin extends SafeEventEmitter implements IPlugin {
  name = "PASSKEYS_PLUGIN";

  private options: IPasskeysPluginOptions;

  private web3auth: ISFAWeb3auth | null = null;

  private initialized: boolean = false;

  private passkeysSvc: PasskeyService | null = null;

  private authInstance: Torus | null = null;

  private nodeDetailManagerInstance: NodeDetailManager;

  private basePrivKey: string;

  private userInfo: OpenloginUserInfo;

  private sessionSignatures: string[];

  private authToken: string;

  private verifier: string;

  constructor(options: IPasskeysPluginOptions) {
    super();
    if (!options.buildEnv) options.buildEnv = BUILD_ENV.PRODUCTION;
    if (!options.rpID) {
      if (typeof window !== "undefined") {
        options.rpID = getTopLevelDomain(window.location.href);
      }
    }
    if (!options.rpName) {
      if (typeof window !== "undefined") {
        options.rpName = getSiteName(window) || "";
      }
    }

    this.options = options;
  }

  async initWithSfaWeb3auth(web3auth: ISFAWeb3auth) {
    if (this.initialized) return;
    if (!web3auth) throw new Error("Web3Auth sfa instance is required");

    this.web3auth = web3auth;
    const { clientId, web3AuthNetwork } = this.web3auth.options;
    if (!clientId || !web3AuthNetwork) throw new Error("Missing Web3auth options");

    this.passkeysSvc = new PasskeyService({
      web3authClientId: clientId,
      web3authNetwork: web3AuthNetwork,
      buildEnv: this.options.buildEnv,
      rpID: this.options.rpID,
      rpName: this.options.rpName,
    });

    this.nodeDetailManagerInstance = new NodeDetailManager({ network: web3AuthNetwork });

    this.authInstance = new Torus({
      clientId,
      enableOneKey: true,
      network: web3AuthNetwork,
    });

    this.verifier = PASSKEYS_VERIFIER_MAP[web3AuthNetwork];

    if (this.web3auth.connected) {
      this.basePrivKey = this.web3auth._getBasePrivKey();
      this.userInfo = await this.web3auth.getUserInfo();
      this.sessionSignatures = this.web3auth.state.sessionSignatures;
      this.authToken = this.web3auth.state.passkeyToken;
    }

    this.subscribeToSfaEvents(web3auth);

    this.initialized = true;
    this.emit(PLUGIN_EVENTS.READY);
  }

  public async registerPasskey({ authenticatorAttachment, username }: RegisterPasskeyParams) {
    if (!this.initialized) throw new Error("Sdk not initialized, please call init first.");
    if (!this.passkeysSvc) throw new Error("Passkey service not initialized");
    if (!this.web3auth.connected) throw new Error("Web3Auth not connected");

    if (!username) {
      username = getUserName(this.userInfo);
    }
    try {
      const { verifier, verifierId, aggregateVerifier } = this.userInfo;
      const result = await this.passkeysSvc.initiateRegistration({
        oAuthVerifier: aggregateVerifier || verifier,
        oAuthVerifierId: verifierId,
        authenticatorAttachment,
        signatures: this.sessionSignatures,
        username,
        passkeyToken: this.authToken,
      });

      if (!result) throw new Error("passkey registration failed.");

      const passkeyVerifierId = await getPasskeyVerifierId(result);

      // get the passkey public address.
      const passkeyPublicKey = await this.getPasskeyPublicKey({ verifier: this.verifier, verifierId: passkeyVerifierId });

      if (!passkeyPublicKey) throw new Error("Unable to get passkey public key, please try again.");

      const encryptedMetadata = await this.getEncryptedMetadata(passkeyPublicKey);

      const verificationResult = await this.passkeysSvc.registerPasskey({
        verificationResponse: result,
        signatures: this.sessionSignatures,
        passkeyToken: this.authToken,
        data: encryptedMetadata,
      });

      if (!verificationResult) throw new Error("passkey registration failed.");

      return true;
    } catch (error: unknown) {
      log.error("error registering user", error);
      throw error;
    }
  }

  public async loginWithPasskey({ authenticatorId }: { authenticatorId?: string } = {}): Promise<SafeEventEmitterProvider | null> {
    if (!this.initialized) throw new Error("Sdk not initialized, please call init first.");
    if (!this.passkeysSvc) throw new Error("Passkey service not initialized");

    const loginResult = await this.passkeysSvc.loginUser(authenticatorId);
    if (!loginResult) throw new Error("passkey login failed.");

    try {
      const {
        response: { signature, clientDataJSON, authenticatorData },
        id,
      } = loginResult.authenticationResponse;
      const { publicKey, challenge, metadata, verifierId } = loginResult.data;

      const loginParams: LoginParams = {
        verifier: this.verifier,
        verifierId,
        idToken: signature,
        extraVerifierParams: {
          signature,
          clientDataJSON,
          authenticatorData,
          publicKey,
          challenge,
          rpOrigin: window.location.origin,
          rpId: this.options.rpID,
          credId: id,
        },
      };

      // get the passkey private key.
      const passkey = await this.getPasskeyPostboxKey(loginParams);

      // decrypt the data.
      const data = await decryptData<MetadataInfo>(passkey, metadata);
      if (!data) throw new Error("Unable to decrypt metadata.");

      await (this.web3auth as ISFAWeb3auth).finalizeLogin({ privKey: data.privKey, userInfo: data.userInfo, passkeyToken: loginResult.data.idToken });
      return (this.web3auth as ISFAWeb3auth).provider;
    } catch (error: unknown) {
      log.error("error login with passkey", error);
      throw error;
    }
  }

  public async listAllPasskeys() {
    if (!this.initialized) throw new Error("Sdk not initialized, please call init first.");
    if (!this.passkeysSvc) throw new Error("Passkey service not initialized");

    return this.passkeysSvc.getAllPasskeys({ passkeyToken: this.authToken, signatures: this.sessionSignatures });
  }

  private async getEncryptedMetadata(passkeyPubKey: TorusPublicKey) {
    const metadata: MetadataInfo = { privKey: this.basePrivKey, userInfo: this.userInfo };

    // encrypting the metadata.
    return encryptData({ x: passkeyPubKey.finalKeyData.X, y: passkeyPubKey.finalKeyData.Y }, metadata);
  }

  private async getPasskeyPublicKey(params: { verifier: string; verifierId: string }) {
    if (!this.initialized) throw new Error("Sdk not initialized, please call init first.");

    const { verifier, verifierId } = params;
    const verifierDetails = { verifier, verifierId };

    const { torusNodeEndpoints, torusNodePub } = await this.nodeDetailManagerInstance.getNodeDetails(verifierDetails);

    const publicAddress = await this.authInstance.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId });
    return publicAddress;
  }

  private async getPasskeyPostboxKey(loginParams: LoginParams): Promise<string> {
    if (!this.initialized) throw new Error("Sdk not initialized, please call init first.");

    const { verifier, verifierId, idToken } = loginParams;
    const verifierDetails = { verifier, verifierId };

    const { torusNodeEndpoints, torusIndexes } = await this.nodeDetailManagerInstance.getNodeDetails(verifierDetails);

    const finalIdToken = idToken;
    const finalVerifierParams = { verifier_id: verifierId };

    const retrieveSharesResponse = await this.authInstance.retrieveShares(
      torusNodeEndpoints,
      torusIndexes,
      verifier,
      finalVerifierParams,
      finalIdToken,
      loginParams.extraVerifierParams || {}
    );

    if (!retrieveSharesResponse.finalKeyData.privKey) throw new Error("Unable to get passkey privkey.");
    return retrieveSharesResponse.finalKeyData.privKey.padStart(64, "0");
  }

  private subscribeToSfaEvents(web3auth: ISFAWeb3auth) {
    web3auth.on(ADAPTER_EVENTS.CONNECTED, async () => {
      this.basePrivKey = web3auth._getBasePrivKey();
      this.userInfo = await web3auth.getUserInfo();
      this.sessionSignatures = web3auth.state.sessionSignatures;
      this.authToken = web3auth.state.passkeyToken;
    });
  }
}
