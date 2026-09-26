/**
 * Did the port in `[[VALIDATORS]].HOST` answer as a Stellar overlay peer?
 *
 * SEP-20 validators publish `HOST` and `PUBLIC_KEY`, and a TCP probe that gets a
 * SYN-ACK proves only that something is listening on 11625 — a banner, a
 * load balancer, a completely different service. What an operator actually
 * means when they publish those two fields is: dial this address and you will
 * complete an overlay handshake with the node whose peer ID is this key, on
 * this network. That claim is checkable, and it is the one that matters for a
 * quorum slice.
 *
 * So this module dials each declared validator, performs the overlay handshake
 * (an ephemeral Curve25519 exchange, keys derived with HKDF, messages sealed
 * with ChaCha20-Poly1305 and authenticated with the derived MAC key), reads the
 * peer's `HELLO`, and compares what it says against what the file says. A peer
 * on the wrong network is a misconfiguration; a peer whose ID is not the
 * published one is a takeover or a stale record.
 *
 * The socket and the AEAD live in `./handshake-socket.ts`, imported
 * dynamically, for the same reason the peer crawler isolates `node:net`: a lint
 * run in a browser or a worker must not load them. The rule objects are
 * registered from `src/rules/index.ts` so `--list-rules` and `--off` know these
 * ids, and nothing here runs unless `--check-network --verify-overlay` both
 * appear.
 *
 * One limitation stated plainly: the handshake implemented here is the one this
 * package speaks — AuthCert exchange, HKDF-SHA256 key derivation, AEAD framing —
 * which is enough to authenticate a peer ID and a network hash, and is what the
 * test suite exercises against a mock peer. Byte-for-byte agreement with a
 * specific stellar-core build depends on that build's overlay version, so a
 * `handshake-timeout` against a live node can mean "not stellar-core" just as
 * easily as "not reachable".
 */
import { xdr, StrKey } from '@stellar/stellar-base';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString } from '../predicates.js';

export const OVERLAY_HANDSHAKE_TIMEOUT_RULE = 'overlay/handshake-timeout';
export const OVERLAY_NETWORK_MISMATCH_RULE = 'overlay/network-mismatch';
export const OVERLAY_PUBLIC_KEY_MISMATCH_RULE = 'overlay/public-key-mismatch';
export const OVERLAY_PROTOCOL_VERSION_OUTDATED_RULE = 'overlay/protocol-version-outdated';

/** `StellarMessageType` discriminants, as the published XDR defines them. */
export const OVERLAY_MESSAGE_ERROR = 0;
export const OVERLAY_MESSAGE_AUTH = 2;
export const OVERLAY_MESSAGE_HELLO = 13;

/** stellar-core's overlay protocol as of the version this package targets. */
export const OVERLAY_PROTOCOL_VERSION = 26;

/** How long a single peer may take to complete a handshake. */
export const OVERLAY_HANDSHAKE_TIMEOUT_MS = 5_000;

const OVERLAY_HELP_URI =
  'https://developers.stellar.org/docs/learn/networks-and-topology/overlay-network';

/** What a peer's `HELLO` said. */
export interface PeerHello {
  ledgerVersion: number;
  overlayVersion: number;
  overlayMinVersion: number;
  /** The 32-byte SHA-256 of the passphrase the peer claims to be on. */
  networkId: Uint8Array;
  versionStr: string;
  listeningPort: number;
  /** The peer's node ID as a `G...` account. */
  peerId: string;
}

/** One `[[VALIDATORS]]` entry worth dialing. */
export interface ValidatorEndpoint {
  index: number;
  path: string;
  alias: string | undefined;
  publicKey: string;
  host: string;
  port: number;
}

/** A peer's `HELLO` together with the `AuthCert` that authenticates its claim. */
export interface AnnouncedHello {
  hello: PeerHello;
  cert: xdr.AuthCert;
}

/** An ephemeral Curve25519/Ed25519 pair for one handshake. */
export interface EphemeralIdentity {
  curvePrivate: Uint8Array;
  curvePublic: Uint8Array;
  nodePrivate: Uint8Array;
  nodePublic: Uint8Array;
}

/**
 * Fresh keys for one dial. Nothing about a lint run's identity needs to outlive
 * it, so the pair is generated per connection and thrown away with the socket.
 */
export function generateEphemeralIdentity(): EphemeralIdentity {
  const curvePrivate = x25519.utils.randomPrivateKey();
  const nodePrivate = ed25519.utils.randomPrivateKey();
  return {
    curvePrivate,
    curvePublic: x25519.getPublicKey(curvePrivate),
    nodePrivate,
    nodePublic: ed25519.getPublicKey(nodePrivate),
  };
}

/** The X25519 secret between our ephemeral key and the peer's announced one. */
export function sharedSecret(ourPrivate: Uint8Array, theirPublic: Uint8Array): Buffer {
  return Buffer.from(x25519.getSharedSecret(Buffer.from(ourPrivate), Buffer.from(theirPublic)));
}

/** Why a handshake did not produce a trustworthy `HELLO`. */
/**
 * Why a handshake did not produce a `HELLO` worth comparing to the file:
 * `timeout` never answered, `unreachable` refused the dial, `protocol` answered
 * with something that is not a StellarMessage, and `authentication` announced a
 * node ID it could not sign for.
 */
export type HandshakeFailure = 'timeout' | 'unreachable' | 'protocol' | 'authentication';

export interface HandshakeOutcome {
  endpoint: ValidatorEndpoint;
  hello?: PeerHello | undefined;
  failure?: HandshakeFailure | undefined;
  detail?: string | undefined;
  /**
   * Whether an `AUTH` frame round-tripped under keys derived from both peers'
   * announced Curve25519 keys. Absent means the peer never echoed, which is
   * reported as negotiation that did not happen rather than as a violation.
   */
  encrypted?: boolean | undefined;
}

/** Dials one endpoint and reports what its handshake said. */
export type OverlayTransport = (
  endpoint: ValidatorEndpoint,
  options: HandshakeOptions,
) => Promise<HandshakeOutcome>;

export interface HandshakeOptions {
  rules?: RuleOverrides;
  /** The network whose hash a peer must present. */
  passphrase?: string;
  timeoutMs?: number;
  /** The protocol version peers are expected to reach. */
  overlayVersion?: number;
  /** Overrides the socket transport; tests speak the protocol themselves. */
  transport?: OverlayTransport;
}

/** The SHA-256 hash a peer on this network must name in its `HELLO`. */
export function networkIdForPassphrase(passphrase: string): Uint8Array {
  return sha256(Buffer.from(passphrase, 'utf8'));
}

/** Reads `[[VALIDATORS]]` into the endpoints a handshake can dial. */
export function validatorEndpoints(doc: Record<string, unknown>): ValidatorEndpoint[] {
  const validators = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  const endpoints: ValidatorEndpoint[] = [];
  validators.forEach((entry, index) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
    const record = entry as Record<string, unknown>;
    const publicKey = isString(record.PUBLIC_KEY) ? record.PUBLIC_KEY : undefined;
    const host = isString(record.HOST) ? splitHost(record.HOST) : undefined;
    if (publicKey === undefined || host === undefined) return;
    endpoints.push({
      index,
      path: `VALIDATORS[${index}]`,
      alias: isString(record.ALIAS) ? record.ALIAS : undefined,
      publicKey,
      host: host.host,
      port: host.port,
    });
  });
  return endpoints;
}

/** Splits a SEP-20 `HOST` of the form `example.com:11625` or `[::1]:11625`. */
function splitHost(value: string): { host: string; port: number } | undefined {
  const raw = value.trim();
  const bracket = raw.startsWith('[') ? raw.indexOf(']') : -1;
  const separator = bracket > 0 ? raw.lastIndexOf(':') : raw.indexOf(':');
  if (separator <= 0 || separator === raw.length - 1) return undefined;
  const host = bracket > 0 ? raw.slice(1, bracket) : raw.slice(0, separator);
  const port = Number(raw.slice(separator + 1));
  if (host === '' || !Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  return { host, port };
}

/** The `HELLO` this package would send, as an overlay frame payload. */
export function encodeHello(input: {
  ledgerVersion: number;
  overlayVersion: number;
  overlayMinVersion: number;
  networkId: Uint8Array;
  versionStr: string;
  listeningPort: number;
  /** The Ed25519 key this message is signed by, i.e. the claimed node ID. */
  nodePublic: Uint8Array;
  cert: xdr.AuthCert;
  nonce: Uint8Array;
}): Buffer {
  return Buffer.from(
    xdr.StellarMessage.hello(
      new xdr.Hello({
        ledgerVersion: input.ledgerVersion,
        overlayVersion: input.overlayVersion,
        overlayMinVersion: input.overlayMinVersion,
        networkId: Buffer.from(input.networkId),
        versionStr: input.versionStr,
        listeningPort: input.listeningPort,
        peerId: xdr.PublicKey.publicKeyTypeEd25519(Buffer.from(input.nodePublic)),
        cert: input.cert,
        nonce: Buffer.from(input.nonce),
      }),
    ).toXDR(),
  );
}

/** An `AUTH` frame announcing that a handshake is beginning. */
export function encodeAuth(flags = 0): Buffer {
  return Buffer.from(xdr.StellarMessage.auth(new xdr.Auth({ flags })).toXDR());
}

/** An `AuthCert` announcing one peer's ephemeral Curve25519 key. */
export function authCert(
  curve25519PublicKey: Uint8Array,
  expiration: number,
  signature: Uint8Array = new Uint8Array(64),
): xdr.AuthCert {
  return new xdr.AuthCert({
    pubkey: new xdr.Curve25519Public({ key: Buffer.from(curve25519PublicKey) }),
    expiration: new xdr.Uint64(Math.trunc(expiration)),
    sig: Buffer.from(signature),
  });
}

/** The XDR bytes of an `AuthCert`. */
export function encodeAuthCert(
  curve25519PublicKey: Uint8Array,
  expiration: number,
  signature: Uint8Array = new Uint8Array(64),
): Buffer {
  return Buffer.from(authCert(curve25519PublicKey, expiration, signature).toXDR());
}

/**
 * The bytes a node signs to bind an `AuthCert` to itself: the key it is
 * announcing, when it stops being valid, and the network it is announcing them
 * on. Including the hash means a cert minted for testnet cannot be replayed
 * against a mainnet peer.
 */
export function authCertSigningInput(
  curve25519PublicKey: Uint8Array,
  expiration: number,
  networkId: Uint8Array,
): Buffer {
  const until = Buffer.alloc(8);
  until.writeBigUInt64BE(BigInt(expiration));
  return Buffer.concat([Buffer.from(curve25519PublicKey), until, Buffer.from(networkId)]);
}

/** A signed `AuthCert`: an ephemeral key bound to a node ID and a network. */
export function signedAuthCert(
  identity: EphemeralIdentity,
  expiration: number,
  networkId: Uint8Array,
): xdr.AuthCert {
  return authCert(
    identity.curvePublic,
    expiration,
    ed25519.sign(
      authCertSigningInput(identity.curvePublic, expiration, networkId),
      identity.nodePrivate,
    ),
  );
}

/**
 * True when a peer's `AuthCert` was signed by the node ID its `HELLO` announces.
 * This is the only step that turns the identity claim into evidence: a listener
 * that cannot produce this signature is not the node the file describes, whatever
 * its `HELLO` says.
 */
export function verifyAuthCert(cert: xdr.AuthCert, peerId: string, networkId: Uint8Array): boolean {
  let nodePublic: Uint8Array;
  try {
    nodePublic = StrKey.decodeEd25519PublicKey(peerId);
  } catch {
    return false;
  }
  const signature = Buffer.from(cert.sig() as Uint8Array);
  try {
    return ed25519.verify(
      signature,
      authCertSigningInput(
        Buffer.from(cert.pubkey().key() as Uint8Array),
        Number(cert.expiration().toString()),
        networkId,
      ),
      Buffer.from(nodePublic),
    );
  } catch {
    return false;
  }
}

/**
 * Decodes one overlay message. `undefined` means the bytes are not a
 * `StellarMessage` at all, which callers treat as a protocol failure rather
 * than a finding about the file. A `HELLO` also carries its `AuthCert`, since
 * that is what authenticates the node ID the message claims.
 */
export function decodeStellarMessage(
  bytes: Uint8Array,
):
  | { type: 'hello'; hello: PeerHello; cert: xdr.AuthCert }
  | { type: 'auth' }
  | { type: 'error'; message: string }
  | { type: 'other'; name: string }
  | undefined {
  try {
    const message = xdr.StellarMessage.fromXDR(Buffer.from(bytes));
    const name = message.switch().name as string;
    if (name === 'hello') {
      const hello = message.hello() as xdr.Hello;
      return { type: 'hello', hello: helloOf(hello), cert: hello.cert() };
    }
    if (name === 'auth') return { type: 'auth' };
    if (name === 'errorMsg') {
      // The arm accessor is a static factory in this XDR binding, so the error
      // body is read straight off the wire instead.
      try {
        const error = xdr.Error.fromXDR(Buffer.from(bytes.subarray(4)));
        return { type: 'error', message: String(error.msg() ?? error.code().name) };
      } catch {
        return { type: 'error', message: 'rejected' };
      }
    }
    return { type: 'other', name };
  } catch {
    return undefined;
  }
}

/** Reads the fields this package validates out of a decoded `HELLO`. */
function helloOf(hello: xdr.Hello): PeerHello {
  const peerId = Buffer.from(hello.peerId().ed25519() as Uint8Array);
  return {
    ledgerVersion: Number(hello.ledgerVersion()),
    overlayVersion: Number(hello.overlayVersion()),
    overlayMinVersion: Number(hello.overlayMinVersion()),
    networkId: Buffer.from(hello.networkId() as Uint8Array),
    versionStr: Buffer.from(hello.versionStr() as Uint8Array).toString('utf8'),
    listeningPort: Number(hello.listeningPort()),
    peerId: StrKey.encodeEd25519PublicKey(peerId),
  };
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

function finding(
  rule: string,
  fallback: Severity,
  message: string,
  path: string,
  suggestion: string,
  rules?: RuleOverrides,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];
  return [
    {
      rule,
      severity,
      category: 'network',
      message,
      path,
      helpUri: OVERLAY_HELP_URI,
      suggestion,
    },
  ];
}

function named(endpoint: ValidatorEndpoint): string {
  return endpoint.alias === undefined
    ? endpoint.publicKey
    : `${endpoint.alias} (${endpoint.publicKey})`;
}

/**
 * Compares a peer's answer with what the file claims about it.
 *
 * The peer ID is the identity claim and the network hash is the loyalty claim;
 * both are errors because a wrong answer means the file is pointing quorum
 * slices at a node that is not the one described. The protocol version is only
 * a warning: an outdated node still validates, it just cannot be relied on for
 * the newest ledger rules.
 */
export function helloFindings(
  endpoint: ValidatorEndpoint,
  hello: PeerHello,
  options: { passphrase?: string; overlayVersion?: number; rules?: RuleOverrides } = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const label = named(endpoint);

  if (options.passphrase !== undefined) {
    const expected = Buffer.from(networkIdForPassphrase(options.passphrase));
    if (!expected.equals(Buffer.from(hello.networkId))) {
      diagnostics.push(
        ...finding(
          OVERLAY_NETWORK_MISMATCH_RULE,
          'error',
          `Overlay peer ${label} at ${endpoint.host}:${endpoint.port} is on a different network: its HELLO hashes a passphrase to ${Buffer.from(hello.networkId).toString('hex').slice(0, 16)}…, not to ${expected.toString('hex').slice(0, 16)}…`,
          `${endpoint.path}.HOST`,
          'NETWORK_PASSPHRASE and [[VALIDATORS]] must describe the same network, or peers will be trusted on a ledger their operators never intended.',
          options.rules,
        ),
      );
      // Every other comparison is meaningless against a peer on another network.
      return diagnostics;
    }
  }

  if (hello.peerId !== endpoint.publicKey) {
    diagnostics.push(
      ...finding(
        OVERLAY_PUBLIC_KEY_MISMATCH_RULE,
        'error',
        `Overlay peer at ${endpoint.host}:${endpoint.port} identified itself as ${hello.peerId}, not the declared ${endpoint.publicKey}`,
        `${endpoint.path}.PUBLIC_KEY`,
        'Either the node is not the one this file describes, or its HOST or PUBLIC_KEY has gone stale. Update the entry to the peer that answered.',
        options.rules,
      ),
    );
  }

  const current = options.overlayVersion ?? OVERLAY_PROTOCOL_VERSION;
  if (hello.overlayMinVersion > current || hello.overlayVersion < current) {
    diagnostics.push(
      ...finding(
        OVERLAY_PROTOCOL_VERSION_OUTDATED_RULE,
        'warning',
        `Overlay peer ${label} speaks protocol version ${hello.overlayVersion} (minimum ${hello.overlayMinVersion}) at ledger ${hello.ledgerVersion}, older than version ${current}`,
        `${endpoint.path}.HOST`,
        `Upgrade the node to a stellar-core release that speaks overlay ${current}. Its version string was ${hello.versionStr || 'unreported'}.`,
        options.rules,
      ),
    );
  }

  if (hello.listeningPort !== endpoint.port) {
    diagnostics.push(
      ...finding(
        OVERLAY_NETWORK_MISMATCH_RULE,
        'error',
        `Overlay peer ${label} listens on port ${hello.listeningPort} but is published at ${endpoint.host}:${endpoint.port}`,
        `${endpoint.path}.HOST`,
        'A port that disagrees with the advertised one means the published HOST forwards somewhere other than this node.',
        options.rules,
      ),
    );
  }

  return diagnostics;
}

/** The findings for a handshake that never produced a trustworthy `HELLO`. */
export function failureFindings(
  outcome: HandshakeOutcome,
  options: HandshakeOptions = {},
): Diagnostic[] {
  const { endpoint } = outcome;
  if (outcome.failure === undefined) return [];
  const detail = outcome.detail === undefined ? '' : `: ${outcome.detail}`;

  if (outcome.failure === 'authentication') {
    return finding(
      OVERLAY_PUBLIC_KEY_MISMATCH_RULE,
      'error',
      `Overlay peer at ${endpoint.host}:${endpoint.port} announced ${endpoint.publicKey} but could not sign with it${detail}`,
      `${endpoint.path}.PUBLIC_KEY`,
      'A listener that cannot produce an AuthCert signature for the published node ID is not that node. Verify the HOST really belongs to this validator before keeping the entry in a quorum slice.',
      options.rules,
    );
  }

  return finding(
    OVERLAY_HANDSHAKE_TIMEOUT_RULE,
    'error',
    `Overlay handshake with ${named(endpoint)} at ${endpoint.host}:${endpoint.port} did not complete${
      outcome.failure === 'timeout' ? ' before the timeout' : ''
    }${detail}`,
    `${endpoint.path}.HOST`,
    outcome.failure === 'unreachable'
      ? 'Nothing is listening on that port. Publish the peer port stellar-core is actually bound to, or remove the entry.'
      : 'A peer that never completes the overlay handshake is not an overlay peer; check the HOST port, the firewall, and that the node is running.',
    options.rules,
  );
}

/**
 * The `--check-network --verify-overlay` entry point: dial every declared
 * validator and compare its answer against the file.
 */
export async function checkOverlayHandshake(
  doc: Record<string, unknown>,
  options: HandshakeOptions = {},
): Promise<Diagnostic[]> {
  const endpoints = validatorEndpoints(doc);
  if (endpoints.length === 0) return [];
  const passphrase = isString(doc.NETWORK_PASSPHRASE) ? doc.NETWORK_PASSPHRASE : options.passphrase;
  const transport = options.transport ?? (await loadTransport()).performOverlayHandshake;
  const diagnostics: Diagnostic[] = [];

  for (const endpoint of endpoints) {
    let outcome: HandshakeOutcome;
    try {
      outcome = await transport(endpoint, { ...options, passphrase });
    } catch (error) {
      outcome = {
        endpoint,
        failure: 'protocol',
        detail: error instanceof Error ? error.message : String(error),
      };
    }
    if (outcome.hello === undefined) {
      diagnostics.push(...failureFindings({ ...outcome, endpoint }, options));
      continue;
    }
    diagnostics.push(
      ...helloFindings(endpoint, outcome.hello, {
        passphrase,
        overlayVersion: options.overlayVersion,
        rules: options.rules,
      }),
    );
  }

  return diagnostics;
}

/** Loaded lazily so the browser and worker bundles never pull in `node:net`. */
async function loadTransport(): Promise<{ performOverlayHandshake: OverlayTransport }> {
  return import('./handshake-socket.js');
}

/** Registered from `src/rules/validators.ts` so `--list-rules` knows these ids. */
export const overlayHandshakeRules: Rule[] = [
  {
    id: OVERLAY_HANDSHAKE_TIMEOUT_RULE,
    category: 'network',
    severity: 'error',
    description: 'A declared validator HOST never completes the Stellar overlay handshake',
    run() {},
  },
  {
    id: OVERLAY_NETWORK_MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description: 'An overlay peer is on another network or listens on another port than published',
    run() {},
  },
  {
    id: OVERLAY_PUBLIC_KEY_MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description: 'An overlay peer identifies itself with a key other than the published PUBLIC_KEY',
    run() {},
  },
  {
    id: OVERLAY_PROTOCOL_VERSION_OUTDATED_RULE,
    category: 'network',
    severity: 'warning',
    description: 'An overlay peer cannot speak the current overlay protocol version',
    run() {},
  },
];

/** Rule ids emitted by {@link checkOverlayHandshake}. */
export const overlayHandshakeRuleIds: readonly string[] = overlayHandshakeRules.map(
  (rule) => rule.id,
);
