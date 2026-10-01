/******************************************************************************

	SMIT5-1Crypto.h: ECDH(P-384) key agreement + AES-256-GCM session cipher

	- asymmetric step: each side generates an ephemeral ECDH P-384 key pair,
	  exports the public part as a BCRYPT_ECCPUBLIC_BLOB and sends it to the
	  other side in the clear (see MessageType::HandshakeInit/Response).

	- both sides then call BCryptSecretAgreement() on (own private key, peer
	  public key) to get the same raw shared secret, and hash it down to a
	  256-bit key with BCryptDeriveKey(..., BCRYPT_KDF_HASH, SHA-256, ...).
	  This is the "set up session key with an asymmetric algorithm" step.

	- the derived 256-bit key is used as an AES-256-GCM key for all further
	  traffic on that connection (the "symmetric encryption with a session
	  key" step). Every message gets its own random 96-bit nonce.

******************************************************************************/

#pragma once

#include "SMIT5-1.h"
#include "SMIT5-1Shared.h"
#include <vector>
#include <span>
#include <cstring>
#include <expected>

namespace crypto {

	inline constexpr size_t AES_KEY_LEN = 32;		// 256-bit
	inline constexpr size_t GCM_NONCE_LEN = 12;	// 96-bit, the size GCM is optimized for
	inline constexpr size_t GCM_TAG_LEN = 16;		// 128-bit authentication tag


	// ---- tiny RAII wrappers around the raw CNG handles -------------------------

	class AlgHandle {
	public:
		AlgHandle() = default;
		explicit AlgHandle(BCRYPT_ALG_HANDLE h) : h_(h) {}
		~AlgHandle() { if (h_) BCryptCloseAlgorithmProvider(h_, 0); }

		AlgHandle(const AlgHandle&) = delete;
		AlgHandle& operator=(const AlgHandle&) = delete;

		AlgHandle(AlgHandle&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
		AlgHandle& operator=(AlgHandle&& o) noexcept {
			if (this != &o) { if (h_) BCryptCloseAlgorithmProvider(h_, 0); h_ = o.h_; o.h_ = nullptr; }
			return *this;
		}

		[[nodiscard]] BCRYPT_ALG_HANDLE get() const { return h_; }

	private:
		BCRYPT_ALG_HANDLE h_ = nullptr;
	};


	class KeyHandle {
	public:
		KeyHandle() = default;
		explicit KeyHandle(BCRYPT_KEY_HANDLE h) : h_(h) {}
		~KeyHandle() { if (h_) BCryptDestroyKey(h_); }

		KeyHandle(const KeyHandle&) = delete;
		KeyHandle& operator=(const KeyHandle&) = delete;

		KeyHandle(KeyHandle&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
		KeyHandle& operator=(KeyHandle&& o) noexcept {
			if (this != &o) { if (h_) BCryptDestroyKey(h_); h_ = o.h_; o.h_ = nullptr; }
			return *this;
		}

		[[nodiscard]] BCRYPT_KEY_HANDLE get() const { return h_; }
		[[nodiscard]] bool valid() const { return h_ != nullptr; }

	private:
		BCRYPT_KEY_HANDLE h_ = nullptr;
	};


	class SecretHandle {
	public:
		SecretHandle() = default;
		explicit SecretHandle(BCRYPT_SECRET_HANDLE h) : h_(h) {}
		~SecretHandle() { if (h_) BCryptDestroySecret(h_); }

		SecretHandle(const SecretHandle&) = delete;
		SecretHandle& operator=(const SecretHandle&) = delete;

		SecretHandle(SecretHandle&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
		SecretHandle& operator=(SecretHandle&& o) noexcept {
			if (this != &o) { if (h_) BCryptDestroySecret(h_); h_ = o.h_; o.h_ = nullptr; }
			return *this;
		}

		[[nodiscard]] BCRYPT_SECRET_HANDLE get() const { return h_; }

	private:
		BCRYPT_SECRET_HANDLE h_ = nullptr;
	};


	// ---- ECDH P-384 ephemeral key pair, used once per connection ---------------

	class EcdhKeyPair {
	public:
		[[nodiscard]] static std::expected<EcdhKeyPair, ReturnCode> generate() {
			BCRYPT_ALG_HANDLE rawAlg = nullptr;
			if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&rawAlg, BCRYPT_ECDH_P384_ALGORITHM, nullptr, 0))) {
				std::println(stderr, "FAIL: BCryptOpenAlgorithmProvider(ECDH_P384) failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}
			crypto::AlgHandle alg{ rawAlg };

			BCRYPT_KEY_HANDLE rawKey = nullptr;
			if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(alg.get(), &rawKey, 384, 0))) {
				std::println(stderr, "FAIL: BCryptGenerateKeyPair failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}
			KeyHandle key{ rawKey };

			if (!BCRYPT_SUCCESS(BCryptFinalizeKeyPair(key.get(), 0))) {
				std::println(stderr, "FAIL: BCryptFinalizeKeyPair failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}

			return EcdhKeyPair{ std::move(alg), std::move(key) };
		}

		// public part, ready to be sent on the wire as-is
		[[nodiscard]] std::expected<std::vector<uint8_t>, ReturnCode> exportPublicBlob() const {
			DWORD needed = 0;
			if (!BCRYPT_SUCCESS(BCryptExportKey(key_.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &needed, 0))) {
				std::println(stderr, "FAIL: BCryptExportKey (size query) failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}

			std::vector<uint8_t> blob(needed);
			DWORD written = 0;
			if (!BCRYPT_SUCCESS(BCryptExportKey(key_.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB,
				blob.data(), static_cast<DWORD>(blob.size()), &written, 0)))
			{
				std::println(stderr, "FAIL: BCryptExportKey failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}
			blob.resize(written);

			return blob;
		}

		// derives a ready-to-use AES-256-GCM key from (our private key, peer's public blob)
		[[nodiscard]] std::expected<KeyHandle, ReturnCode> deriveAesKey(
			std::span<const uint8_t> peerPublicBlob) const
		{
			BCRYPT_KEY_HANDLE rawPeerKey = nullptr;
			if (!BCRYPT_SUCCESS(BCryptImportKeyPair(
				alg_.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, &rawPeerKey,
				const_cast<PUCHAR>(peerPublicBlob.data()),
				static_cast<ULONG>(peerPublicBlob.size()), 0)))
			{
				std::println(stderr, "FAIL: BCryptImportKeyPair (peer public key) failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}
			KeyHandle peerKey{ rawPeerKey };

			BCRYPT_SECRET_HANDLE rawSecret = nullptr;
			if (!BCRYPT_SUCCESS(BCryptSecretAgreement(key_.get(), peerKey.get(), &rawSecret, 0))) {
				std::println(stderr, "FAIL: BCryptSecretAgreement failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}
			SecretHandle secret{ rawSecret };

			// hash-KDF: SHA-256(raw ECDH secret) -> 32-byte AES key
			BCryptBuffer paramBuf{
				.cbBuffer = static_cast<ULONG>((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(wchar_t)),
				.BufferType = KDF_HASH_ALGORITHM,
				.pvBuffer = const_cast<wchar_t*>(BCRYPT_SHA256_ALGORITHM)
			};
			BCryptBufferDesc paramDesc{
				.ulVersion = BCRYPTBUFFER_VERSION,
				.cBuffers = 1,
				.pBuffers = &paramBuf
			};

			DWORD needed = 0;
			if (!BCRYPT_SUCCESS(BCryptDeriveKey(secret.get(), BCRYPT_KDF_HASH, &paramDesc, nullptr, 0, &needed, 0))) {
				std::println(stderr, "FAIL: BCryptDeriveKey (size query) failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}

			std::vector<uint8_t> derived(needed);
			DWORD written = 0;
			if (!BCRYPT_SUCCESS(BCryptDeriveKey(secret.get(), BCRYPT_KDF_HASH, &paramDesc,
				derived.data(), static_cast<DWORD>(derived.size()), &written, 0)))
			{
				std::println(stderr, "FAIL: BCryptDeriveKey failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}
			derived.resize(written); // 32 bytes for SHA-256

			BCRYPT_ALG_HANDLE rawAesAlg = nullptr;
			if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&rawAesAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
				std::println(stderr, "FAIL: BCryptOpenAlgorithmProvider(AES) failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}
			AlgHandle aesAlg{ rawAesAlg };

			if (!BCRYPT_SUCCESS(BCryptSetProperty(aesAlg.get(), BCRYPT_CHAINING_MODE,
				reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
				static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)), 0)))
			{
				std::println(stderr,
					"FAIL: BCryptSetProperty(GCM) failed --- GCM not supported by this provider/OS");
				// Win7 w/o SP may cause issues??
				return std::unexpected(ReturnCode::UnexpectedError);
			}

			BCRYPT_KEY_HANDLE rawAesKey = nullptr;
			if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(aesAlg.get(), &rawAesKey, nullptr, 0,
				derived.data(), static_cast<ULONG>(derived.size()), 0)))
			{
				std::println(stderr, "FAIL: BCryptGenerateSymmetricKey failed");
				return std::unexpected(ReturnCode::UnexpectedError);
			}

			// the AES key does not need the algorithm handle to stay open
			return KeyHandle{ rawAesKey };
		}

	private:
		EcdhKeyPair(AlgHandle alg, KeyHandle key) : alg_(std::move(alg)), key_(std::move(key)) {}

		AlgHandle alg_;
		KeyHandle key_;
	};


	// ---- AES-256-GCM one-shot encrypt/decrypt ----------------------------------
	// wire format: [12-byte nonce][ciphertext, same length as plaintext][16-byte tag]

	[[nodiscard]] inline std::expected<std::vector<uint8_t>, ReturnCode> aesGcmEncrypt(
		BCRYPT_KEY_HANDLE key, std::span<const uint8_t> plaintext)
	{
		std::vector<uint8_t> nonce(GCM_NONCE_LEN);
		if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, nonce.data(),
			static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
		{
			std::println(stderr, "FAIL: BCryptGenRandom (nonce) failed");
			return std::unexpected(ReturnCode::UnexpectedError);
		}

		std::vector<uint8_t> tag(GCM_TAG_LEN);
		std::vector<uint8_t> ciphertext(plaintext.size());

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
		BCRYPT_INIT_AUTH_MODE_INFO(info);
		info.pbNonce = nonce.data();
		info.cbNonce = static_cast<ULONG>(nonce.size());
		info.pbTag = tag.data();
		info.cbTag = static_cast<ULONG>(tag.size());

		ULONG written = 0;
		if (!BCRYPT_SUCCESS(BCryptEncrypt(
			key,
			const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
			&info,
			nullptr, 0,
			ciphertext.empty() ? nullptr : ciphertext.data(), static_cast<ULONG>(ciphertext.size()),
			&written, 0)))
		{
			std::println(stderr, "FAIL: BCryptEncrypt (AES-GCM) failed");
			return std::unexpected(ReturnCode::UnexpectedError);
		}
		ciphertext.resize(written);

		std::vector<uint8_t> out;
		out.reserve(nonce.size() + ciphertext.size() + tag.size());
		out.insert(out.end(), nonce.begin(), nonce.end());
		out.insert(out.end(), ciphertext.begin(), ciphertext.end());
		out.insert(out.end(), tag.begin(), tag.end());

		return out;
	}


	[[nodiscard]] inline std::expected<std::vector<uint8_t>, ReturnCode> aesGcmDecrypt(
		BCRYPT_KEY_HANDLE key, std::span<const uint8_t> framed)
	{
		if (framed.size() < GCM_NONCE_LEN + GCM_TAG_LEN) {
			std::println(stderr, "FAIL: encrypted frame too small");
			return std::unexpected(ReturnCode::InvalidValue);
		}

		const auto nonce = framed.subspan(0, GCM_NONCE_LEN);
		const auto tag = framed.subspan(framed.size() - GCM_TAG_LEN, GCM_TAG_LEN);
		const auto ciphertext = framed.subspan(GCM_NONCE_LEN, framed.size() - GCM_NONCE_LEN - GCM_TAG_LEN);

		std::vector<uint8_t> plaintext(ciphertext.size());

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
		BCRYPT_INIT_AUTH_MODE_INFO(info);
		info.pbNonce = const_cast<PUCHAR>(nonce.data());
		info.cbNonce = static_cast<ULONG>(nonce.size());
		info.pbTag = const_cast<PUCHAR>(tag.data());
		info.cbTag = static_cast<ULONG>(tag.size());

		ULONG written = 0;
		const NTSTATUS status = BCryptDecrypt(
			key,
			const_cast<PUCHAR>(ciphertext.data()), static_cast<ULONG>(ciphertext.size()),
			&info,
			nullptr, 0,
			plaintext.empty() ? nullptr : plaintext.data(), static_cast<ULONG>(plaintext.size()),
			&written, 0);

		if (!BCRYPT_SUCCESS(status)) {
			// a mismatched tag (tampering/corruption/wrong key) ends up here too
			std::println(stderr, "FAIL: BCryptDecrypt (AES-GCM) failed (status {:#010x})",
				static_cast<uint32_t>(status));
			return std::unexpected(ReturnCode::UnexpectedError);
		}
		plaintext.resize(written);

		return plaintext;
	}

} // namespace crypto
