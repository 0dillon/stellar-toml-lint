/**
 * The socket half of the overlay handshake.
 *
 * Everything here needs a Node runtime — `node:net` for the dial, `node:crypto`
 * for HKDF and ChaCha20-Poly1305 — so it lives apart from `handshake.ts`, which
 * imports it lazily. A lint run in a browser or a worker never loads this file,
 * exactly as the peer crawler keeps `node-connector.ts` to itself.
 *
 * On the wire, in the order the overlay speaks it:
 *
 * 1. each side opens with an unencrypted `HELLO`, framed as
 *    `uint32 length ‖ StellarMessage`. Every finding this package reports comes
 *    out of that frame, which is why linting a file never requires decryption.
 * 2. a `HELLO` carries an `AuthCert` — an ephemeral Curve25519 key, an expiry,
 *    and an Ed25519 signature over both plus the network hash — so the node ID
 *    the peer claims is checked against a signature rather than against a claim.
 *    The hash in that signature is the one the `HELLO` names, which keeps the
 *    identity question separate from the network question.
 * 3. both sides then derive 96 bytes with HKDF-SHA256 over their X25519 shared
 *    secret (send key, receive key, MAC key, mirrored by role) and exchange one
 *    `AUTH` frame as `nonce ‖ ciphertext ‖ tag ‖ mac`, sealed with
 *    ChaCha20-Poly1305 and authenticated with HMAC-SHA256.
 * 4. the connection closes.
 *
 * Step 3 is attempted and never required: what a node sends after its `HELLO`
 * depends on its overlay version and on whether it decided to keep this
 * connection at all, so an echo that does not open means "the AEAD path was not
 * negotiated with us" rather than "the file is wrong". Step 2 is required — a
 * peer that cannot sign with the node ID it announces is not that peer.
 */
import { createConnection, type Socket } from 'node:net';
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { StrKey } from '@stellar/stellar-base';
import {
  decodeStellarMessage,
  encodeAuth,
  encodeHello,
  networkIdForPassphrase,
  sharedSecret,
  signedAuthCert,
  verifyAuthCert,
  OVERLAY_HANDSHAKE_TIMEOUT_MS,
  OVERLAY_MESSAGE_AUTH,
  OVERLAY_PROTOCOL_VERSION,
  generateEphemeralIdentity,
  type AnnouncedHello,
  type EphemeralIdentity,
  type HandshakeFailure,
  type HandshakeOptions,
  type HandshakeOutcome,
  type PeerHello,
  type ValidatorEndpoint,
} from './handshake.js';
import { frameOverlayMessage, OVERLAY_MAX_FRAME_BYTES } from './crawler.js';

export { generateEphemeralIdentity, signedAuthCert, verifyAuthCert };
export type { EphemeralIdentity };

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const MAC_BYTES = 32;
const KEY_BYTES = 32;
/** A `HELLO` is ~240 bytes; a peer that sends megabytes is not answering us. */
const MAX_HELLO_BYTES = 4096;

const HKDF_INFO = Buffer.from('stellar-overlay-auth-v1', 'utf8');

/** The three keys one direction of a handshake uses. */
export interface SessionKeys {
  send: Buffer;
  receive: Buffer;
  mac: Buffer;
}

/**
 * HKDF-SHA256 over the X25519 shared secret, split into send/receive/MAC and
 * mirrored by role so the two peers agree on who reads which half.
 */
export function deriveSessionKeys(
  sharedSecret: Uint8Array,
  salt: Uint8Array,
  oursAreFirst: boolean,
): SessionKeys {
  const material = Buffer.from(
    hkdfSync('sha256', Buffer.from(sharedSecret), Buffer.from(salt), HKDF_INFO, KEY_BYTES * 3),
  );
  const first = material.subarray(0, KEY_BYTES);
  const second = material.subarray(KEY_BYTES, KEY_BYTES * 2);
  const mac = material.subarray(KEY_BYTES * 2, KEY_BYTES * 3);
  return oursAreFirst
    ? { send: Buffer.from(first), receive: Buffer.from(second), mac: Buffer.from(mac) }
    : { send: Buffer.from(second), receive: Buffer.from(first), mac: Buffer.from(mac) };
}

/**
 * `nonce ‖ ciphertext ‖ tag ‖ mac`, where the AEAD additionally binds the
 * payload to `header` so a sealed frame cannot be replayed into another slot of
 * the exchange.
 */
export function sealFrame(keys: SessionKeys, plaintext: Uint8Array, header: Uint8Array): Buffer {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('chacha20-poly1305', keys.send, nonce, {
    authTagLength: TAG_BYTES,
  });
  cipher.setAAD(Buffer.from(header), { plaintextLength: plaintext.length });
  const body = Buffer.concat([
    cipher.update(Buffer.from(plaintext)),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  const frame = Buffer.concat([nonce, body]);
  return Buffer.concat([frame, createHmac('sha256', keys.mac).update(frame).digest()]);
}

/** The inverse of {@link sealFrame}; `undefined` when authentication fails. */
export function openFrame(
  keys: SessionKeys,
  frame: Uint8Array,
  header: Uint8Array,
): Buffer | undefined {
  const bytes = Buffer.from(frame);
  if (bytes.length < NONCE_BYTES + TAG_BYTES + MAC_BYTES) return undefined;
  const sealed = bytes.subarray(0, bytes.length - MAC_BYTES);
  const mac = bytes.subarray(bytes.length - MAC_BYTES);
  const expected = createHmac('sha256', keys.mac).update(sealed).digest();
  if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) return undefined;

  const nonce = sealed.subarray(0, NONCE_BYTES);
  const body = sealed.subarray(NONCE_BYTES);
  const ciphertext = body.subarray(0, body.length - TAG_BYTES);
  try {
    const decipher = createDecipheriv('chacha20-poly1305', keys.receive, nonce, {
      authTagLength: TAG_BYTES,
    });
    decipher.setAAD(Buffer.from(header), { plaintextLength: ciphertext.length });
    decipher.setAuthTag(body.subarray(body.length - TAG_BYTES));
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return undefined;
  }
}

/** The `AUTH` echo is sealed against the message type it carries. */
function authHeader(): Buffer {
  const header = Buffer.alloc(8);
  header.writeUInt32BE(OVERLAY_MESSAGE_AUTH, 0);
  return header;
}

/** One step of the exchange: a whole frame, or the failure that stopped us. */
type Step = { frame: Uint8Array } | { failure: HandshakeFailure; detail?: string };

/**
 * Waits for a single frame and rejects nothing: a timeout, a closed socket, or a
 * malformed length all come back as a classified failure, because a peer that is
 * down is a finding about the file rather than an error in the run.
 */
function nextFrame(socket: Socket, stopped: (message: string) => Step): Promise<Step> {
  return new Promise((resolve) => {
    let settled = false;
    let buffer: Uint8Array = new Uint8Array(0);

    const finish = (step: Step): void => {
      if (settled) return;
      settled = true;
      socket.off('data', onData);
      socket.off('close', onClose);
      socket.off('error', onError);
      resolve(step);
    };
    const onData = (chunk: Uint8Array): void => {
      buffer = new Uint8Array([...buffer, ...chunk]);
      if (buffer.length < 4) return;
      const length = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint32(0);
      if (length === 0 || length > MAX_HELLO_BYTES) {
        finish({ failure: 'protocol', detail: `peer declared a ${length}-byte frame` });
        return;
      }
      if (buffer.length >= length + 4) finish({ frame: buffer.subarray(4, length + 4) });
    };
    const onClose = (): void => finish(stopped('the peer closed the connection mid-handshake'));
    const onError = (error: Error): void => finish(stopped(error.message));
    socket.on('data', onData);
    socket.once('close', onClose);
    socket.once('error', onError);
  });
}

/**
 * Dials one validator and performs the handshake described above. Never throws:
 * every transport outcome is a classified {@link HandshakeOutcome}.
 */
export async function performOverlayHandshake(
  endpoint: ValidatorEndpoint,
  options: HandshakeOptions = {},
): Promise<HandshakeOutcome> {
  const timeoutMs = options.timeoutMs ?? OVERLAY_HANDSHAKE_TIMEOUT_MS;
  const networkId =
    options.passphrase === undefined
      ? new Uint8Array(32)
      : networkIdForPassphrase(options.passphrase);
  const identity = generateEphemeralIdentity();
  // The cert is valid for the run plus a minute; a peer that would accept a
  // much longer window is not the peer this file is describing.
  const expiration = Math.floor(Date.now() / 1000) + Math.ceil(timeoutMs / 1000) + 60;

  const socket = createConnection({ host: endpoint.host, port: endpoint.port });
  socket.setNoDelay(true);
  const deadline = new Promise<Step>((resolve) => {
    socket.setTimeout(timeoutMs, () =>
      resolve({ failure: 'timeout', detail: `no overlay reply within ${timeoutMs}ms` }),
    );
  });

  try {
    const connected = await Promise.race([connectionStep(socket), deadline]);
    if ('failure' in connected) return { endpoint, ...connected };

    socket.write(
      frameOverlayMessage(
        encodeHello({
          ledgerVersion: 1,
          overlayVersion: options.overlayVersion ?? OVERLAY_PROTOCOL_VERSION,
          overlayMinVersion: 1,
          networkId,
          versionStr: 'stellar-toml-lint',
          listeningPort: endpoint.port,
          nodePublic: identity.nodePublic,
          cert: signedAuthCert(identity, expiration, networkId),
          nonce: randomBytes(32),
        }),
      ),
    );

    const answer = await Promise.race([
      nextFrame(socket, (detail) => ({ failure: 'protocol', detail })),
      deadline,
    ]);
    if ('failure' in answer) return { endpoint, ...answer };

    const decoded = decodeStellarMessage(answer.frame);
    if (decoded === undefined || decoded.type !== 'hello') {
      return {
        endpoint,
        failure: 'protocol',
        detail:
          decoded === undefined
            ? 'peer sent bytes that are not a StellarMessage'
            : `peer answered with '${decoded.type}' instead of HELLO`,
      };
    }

    // The cert is checked against the network the peer itself names, because
    // verifying a signature and disbelieving a claim are different questions: a
    // peer on the wrong network is still a peer that knows its own key.
    if (!verifyAuthCert(decoded.cert, decoded.hello.peerId, decoded.hello.networkId)) {
      return {
        endpoint,
        failure: 'authentication',
        detail: `the AuthCert in its HELLO is not signed by ${decoded.hello.peerId}`,
      };
    }

    const echo = await negotiateEncryption(socket, identity, decoded, networkId, deadline);
    return { endpoint, hello: decoded.hello, encrypted: echo };
  } catch (error) {
    return {
      endpoint,
      failure: 'protocol',
      detail: error instanceof Error ? error.message : String(error),
    };
  } finally {
    socket.destroy();
  }
}

/** Resolves once the TCP connection lands or the dial fails outright. */
function connectionStep(socket: Socket): Promise<Step> {
  return new Promise((resolve) => {
    socket.once('connect', () => resolve({ frame: new Uint8Array(0) }));
    socket.once('error', (error: Error) =>
      resolve({
        failure:
          (error as NodeJS.ErrnoException).code === 'ECONNREFUSED' ? 'unreachable' : 'timeout',
        detail: error.message,
      }),
    );
  });
}

/**
 * Derives the session keys from the two announced Curve25519 keys and trades one
 * sealed `AUTH` frame with the peer. `undefined` means the echo never came back,
 * which the caller reports as negotiation that did not happen rather than as a
 * violation.
 */
async function negotiateEncryption(
  socket: Socket,
  identity: EphemeralIdentity,
  peer: AnnouncedHello,
  networkId: Uint8Array,
  deadline: Promise<Step>,
): Promise<boolean | undefined> {
  const keys = deriveSessionKeys(
    sharedSecret(identity.curvePrivate, Buffer.from(peer.cert.pubkey().key() as Uint8Array)),
    networkId,
    true,
  );
  const header = authHeader();
  socket.write(frameOverlayMessage(sealFrame(keys, encodeAuth(), header)));

  const echo = await Promise.race([nextFrame(socket, () => ({ failure: 'protocol' })), deadline]);
  if ('failure' in echo) return undefined;
  return openFrame(keys, echo.frame, header) !== undefined;
}

/** The peer side of the exchange, so a test can stand in for a validator. */
export interface MockPeerOptions {
  /** What this peer's `HELLO` says, minus the identity, which is declared. */
  hello: Omit<PeerHello, 'peerId' | 'networkId'> & { networkId?: Uint8Array };
  /**
   * The Ed25519 seed that signs the `AuthCert`. A peer announces one node ID and
   * signs with this key, so a seed belonging to some other node is how a test
   * models a listener that cannot prove the identity it claims.
   */
  nodePrivate: Uint8Array;
  /** Announces this node ID; defaults to the one the file declares. */
  peerId?: string;
  /** Answers the `HELLO` at all. */
  silent?: boolean;
  /** Answers with bytes that are not a `StellarMessage`. */
  garbage?: boolean;
  /** Drops the connection as soon as our `HELLO` arrives. */
  hangUp?: boolean;
  /** Sends an `AUTH` echo the client cannot authenticate. */
  tamper?: boolean;
  timeoutMs?: number;
}

/**
 * Speaks the peer half of the handshake over an accepted socket: read the
 * client's `HELLO`, answer with our own, then trade one sealed `AUTH` echo.
 *
 * Exported for the test suite. A mock validator built from the same primitives
 * proves the framing, the identity signature, and the AEAD handling round-trip,
 * which is the part of this module that can be checked without a live network.
 */
export async function respondAsOverlayPeer(
  socket: Socket,
  options: MockPeerOptions,
  announcedNetworkId: Uint8Array,
  declaredPeerId: string,
): Promise<void> {
  const frames = readFrames(socket, options.timeoutMs ?? 5_000);
  const clientHello = await frames.next();
  if (clientHello === undefined || options.silent) return;
  if (options.hangUp) {
    socket.destroy();
    return;
  }
  if (options.garbage) {
    socket.write(frameOverlayMessage(Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])));
    socket.end();
    return;
  }

  const identity = generateEphemeralIdentity();
  const peerId = options.peerId ?? declaredPeerId;
  const networkId = options.hello.networkId ?? announcedNetworkId;
  const expiration = Math.floor(Date.now() / 1000) + 600;
  const cert = signedAuthCert(
    { ...identity, nodePrivate: options.nodePrivate },
    expiration,
    networkId,
  );
  socket.write(
    frameOverlayMessage(
      encodeHello({
        ledgerVersion: options.hello.ledgerVersion,
        overlayVersion: options.hello.overlayVersion,
        overlayMinVersion: options.hello.overlayMinVersion,
        networkId,
        versionStr: options.hello.versionStr,
        listeningPort: options.hello.listeningPort,
        nodePublic: StrKey.decodeEd25519PublicKey(peerId),
        cert,
        nonce: randomBytes(32),
      }),
    ),
  );

  const sealed = await frames.next();
  const clientCurve = clientCurveOf(clientHello);
  if (sealed === undefined || clientCurve === undefined) return;
  const keys = deriveSessionKeys(
    sharedSecret(identity.curvePrivate, clientCurve),
    networkId,
    false,
  );
  // A peer that cannot open our frame has no reason to keep the connection up,
  // and the client's own seal is what this proves: only an authenticated echo
  // comes back.
  if (openFrame(keys, sealed, authHeader()) === undefined) {
    socket.destroy();
    return;
  }
  socket.write(
    frameOverlayMessage(
      sealFrame(
        options.tamper ? { ...keys, mac: Buffer.alloc(MAC_BYTES) } : keys,
        encodeAuth(),
        authHeader(),
      ),
    ),
  );
  socket.end();
}

/** The Curve25519 key the client announced inside its own `HELLO`. */
function clientCurveOf(helloFrame: Uint8Array): Uint8Array | undefined {
  const decoded = decodeStellarMessage(helloFrame);
  if (decoded === undefined || decoded.type !== 'hello') return undefined;
  return Buffer.from(decoded.cert.pubkey().key() as Uint8Array);
}

/** Yields each length-prefixed frame the socket delivers, or `undefined`. */
function readFrames(
  socket: Socket,
  timeoutMs: number,
): { next: () => Promise<Uint8Array | undefined> } {
  let buffer: Uint8Array = new Uint8Array(0);
  const waiting: ((frame: Uint8Array | undefined) => void)[] = [];

  const take = (): Uint8Array | undefined => {
    if (buffer.length < 4) return undefined;
    const length = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint32(0);
    if (length === 0 || length > OVERLAY_MAX_FRAME_BYTES) {
      buffer = new Uint8Array(0);
      return undefined;
    }
    if (buffer.length < length + 4) return undefined;
    const frame = buffer.subarray(4, length + 4);
    buffer = buffer.subarray(length + 4);
    return frame;
  };
  const deliver = (frame: Uint8Array | undefined): void => {
    const waiter = waiting.shift();
    if (waiter !== undefined) waiter(frame);
    else if (frame !== undefined) buffer = new Uint8Array([...buffer, ...frame]);
  };

  socket.on('data', (chunk: Uint8Array) => {
    buffer = new Uint8Array([...buffer, ...chunk]);
    for (;;) {
      const frame = take();
      if (frame === undefined) return;
      deliver(frame);
    }
  });
  socket.once('close', () => deliver(undefined));
  socket.once('error', () => deliver(undefined));

  return {
    next: () =>
      new Promise((resolve) => {
        const buffered = take();
        if (buffered !== undefined) {
          resolve(buffered);
          return;
        }
        waiting.push(resolve);
        socket.setTimeout(timeoutMs, () => resolve(undefined));
      }),
  };
}
