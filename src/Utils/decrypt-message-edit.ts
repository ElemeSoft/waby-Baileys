import type Long from 'long'
import { proto } from '../../WAProto/index.js'
import { aesDecryptGCM, hmacSign } from './crypto'
import { toNumber } from './generics'
import type { ILogger } from './logger'

export type SecretEncryptedMessage = proto.Message.ISecretEncryptedMessage

export type DecryptedEditResult = {
	editedContent: proto.IMessage
	protocolMessage: proto.Message.IProtocolMessage
}

/**
 * Decrypt a secret encrypted message edit.
 *
 * This utility encapsulates the full decryption pipeline:
 * 1. Validation of inputs
 * 2. Key derivation from the original message secret
 * 3. AES-GCM decryption
 * 4. Protobuf decoding
 * 5. Construction of the ProtocolMessage wrapper
 *
 * @param secretEnc - The secret encrypted message payload
 * @param messageSecret - The original message's messageSecret from messageContextInfo
 * @param targetMsgId - ID of the message being edited
 * @param editSender - JID of the sender performing the edit
 * @param logger - Optional logger for debug output
 * @returns The decrypted edit result, or null if decryption fails
 */
export function decryptMessageEdit(
	secretEnc: SecretEncryptedMessage,
	messageSecret: Uint8Array | Buffer | string,
	targetMsgId: string,
	editSender: string,
	logger?: ILogger
): DecryptedEditResult | null {
	if (!secretEnc.encPayload || !secretEnc.encIv) {
		logger?.warn({ targetMsgId }, 'missing encPayload or encIv for edit decryption')
		return null
	}

	const origMsgSecret =
		typeof messageSecret === 'string' ? Buffer.from(messageSecret, 'base64') : Buffer.from(messageSecret)

	const sign = Buffer.concat([
		Buffer.from(targetMsgId),
		Buffer.from(editSender),
		Buffer.from(editSender),
		Buffer.from('Message Edit'),
		new Uint8Array([1])
	])

	const key0 = hmacSign(origMsgSecret, new Uint8Array(32), 'sha256')
	const decKey = hmacSign(sign, key0, 'sha256')
	const decrypted = aesDecryptGCM(secretEnc.encPayload, decKey, secretEnc.encIv, Buffer.alloc(0))

	const decoded = proto.Message.decode(decrypted)
	const editContent = decoded.protocolMessage?.editedMessage || decoded

	const protocolMsg: proto.Message.IProtocolMessage = {
		key: secretEnc.targetMessageKey,
		editedMessage: editContent,
		timestampMs: Date.now(),
		type: proto.Message.ProtocolMessage.Type.MESSAGE_EDIT
	}

	return { editedContent: editContent, protocolMessage: protocolMsg }
}

/**
 * Apply a decrypted message edit to a WAMessage.
 * Sets the message content to the constructed protocolMessage.
 *
 * @param msg - The message to apply the edit to
 * @param protocolMessage - The constructed protocol message from decryptMessageEdit
 * @param messageTimestamp - The original message timestamp (used for timestampMs fallback)
 */
export function applyMessageEdit(
	msg: { message?: proto.IMessage | null; messageTimestamp?: number | Long | null },
	protocolMessage: proto.Message.IProtocolMessage,
	messageTimestamp?: number | Long | null
): void {
	if (!protocolMessage.timestampMs || protocolMessage.timestampMs === Date.now()) {
		protocolMessage.timestampMs = messageTimestamp ? toNumber(messageTimestamp) * 1000 : Date.now()
	}

	msg.message = {
		protocolMessage
	}
}
