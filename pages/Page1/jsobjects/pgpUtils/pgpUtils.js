export default {
	init() {
		storeValue("txt_info_key","info..");
	},
	/* ============ Utils ============ */

	_extractBase64(s) {
		if (!s || typeof s !== "string") throw new Error("Dato base64 non valido");
		return s.replace(/^data:.*;base64,/, "");
	},

	_b64ToText(src) {
		const b64 = this._extractBase64(src);
		const bin = atob(b64);
		const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
		return new TextDecoder("utf-8").decode(bytes);
	},

	_b64ToBytes(src) {
		const b64 = this._extractBase64(src);
		const bin = atob(b64);
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	},

	_uint8ToBase64(uint8) {
		let binary = "";
		for (let i = 0; i < uint8.length; i++) binary += String.fromCharCode(uint8[i]);
		return btoa(binary);
	},

	_getFileFromPicker(picker, idx = 0) {
		const f = picker?.files?.[idx];
		if (!f) throw new Error("Nessun file selezionato.");
		return f;
	},

	// Isola SOLO il blocco PUBLIC KEY e normalizza le newline
	_extractArmoredPublicKey(text) {
		const cleaned = (text || "").replace(/^\uFEFF/, "").trim();
		const re = /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/m;
		const m = cleaned.match(re);
		if (!m) throw new Error("Blocco 'PGP PUBLIC KEY' non trovato nel file .asc");
		return m[0].replace(/\r\n/g, "\n").replace(/[ \t]+$/gm, "");
	},

	_armoredFromKeyPicker(keyPicker) {
		const f = this._getFileFromPicker(keyPicker);
		const src = f.data || f.dataURL;
		if (!src) throw new Error("File chiave non valido.");
		const text = this._b64ToText(src);
		return this._extractArmoredPublicKey(text);
	},

	_formatDate(dt) {
		if (!dt) return "N/D";
		try { return dt.toISOString().slice(0,19).replace("T"," "); } catch { return "N/D"; }
	},

	/* ============ Controllo upload + estrazione info su txt_info_key ============ */
	/**
   * Da collegare a onFilesSelected del FilePicker della chiave
   * opts: { widgetName?: string, formName?: string, useToggle?: boolean }
   * Mostra info in appsmith.store.txt_info_key e blocca PRIVATE KEY.
   */
	async controllaUploadChiavePubblica(keyPicker, opts = {}) {
		try {
			const f = this._getFileFromPicker(keyPicker);
			const src = f.data || f.dataURL;
			if (!src) throw new Error("File chiave non valido.");

			const rawText = this._b64ToText(src).replace(/^\uFEFF/, "").trim();

			// 1) PRIVATE/SECRET KEY -> reset e messaggio
			if (/-----BEGIN PGP (?:SECRET|PRIVATE) KEY BLOCK-----/i.test(rawText)) {
				const msg = "❌ Hai caricato una PRIVATE KEY. Per cifrare serve la PUBLIC KEY del destinatario.";
				await storeValue("txt_info_key", msg);
				showAlert(msg, "error");
				await resetWidget(opts.formName, true);
				return false;
			}

			// 2) Estrai blocco PUBLIC KEY e parse con OpenPGP.js
			const armoredPub = this._extractArmoredPublicKey(rawText);
			const key = await openpgp.readKey({ armoredKey: armoredPub });

			// 3) Metadati chiave
			const fingerprint = key.getFingerprint?.() || "N/D";
			const userIDs = (key.getUserIDs?.() || []);
			const primaryUID = userIDs[0] || "N/D";
			const createdAt = key.getCreationTime?.() || null;
			const createdStr = this._formatDate(createdAt);

			let expiresStr = "Nessuna (non scade)";
			try {
				const exp = await (key.getExpirationTime?.() || Promise.resolve(null));
				if (exp) expiresStr = this._formatDate(exp);
			} catch (_) {}

			let revokedStr = "No";
			try {
				const revoked = await (key.isRevoked?.() || Promise.resolve(false));
				revokedStr = revoked ? "Sì" : "No";
			} catch (_) {}

			// 4) Pre-test cifratura (per intercettare ElGamal o assenza subkey encr)
			let encryptSupport = "OK";
			try {
				const testMsg = await openpgp.createMessage({ binary: new Uint8Array([0x00]) });
				await openpgp.encrypt({ message: testMsg, encryptionKeys: [key], format: "binary" });
			} catch (e) {
				const em = (e?.message || "").toLowerCase();
				if (em.includes("elgamal")) {
					encryptSupport = "NON SUPPORTATA (ElGamal non accettato da OpenPGP.js)";
				} else {
					encryptSupport = `Problema: ${e?.message || "errore cifratura di test"}`;
				}
			}

			// 5) Riepilogo su txt_info_key
			const infoText =
						`✅ PUBLIC KEY caricata
Fingerprint: ${fingerprint}
UserID: ${primaryUID}
Creato il: ${createdStr}
Scadenza: ${expiresStr}
Revocata: ${revokedStr}
Cifratura supportata: ${encryptSupport}`;

			await storeValue("txt_info_key", infoText);

			// Alert conclusivo
			if (encryptSupport === "OK") {
				showAlert("✅ Public key valida e utilizzabile per la cifratura.", "success");
			} else {
				showAlert("⚠️ Public key caricata ma non utilizzabile per la cifratura. Vedi dettagli.", "warning");
							await resetWidget(opts.formName, true);
			}

			return true;

		} catch (e) {
			const msg = `❌ Chiave non valida: ${e?.message || e}`;
			await storeValue("txt_info_key", msg);
			showAlert(msg, "error");
			await resetWidget(opts.formName, true);
			return false;
		}
	},

	/* ============ (Opzionale) Validator semplice richiamabile da bottone ============ */
	async validaChiavePubblica(keyPicker) {
		const armor = this._armoredFromKeyPicker(keyPicker);
		const key = await openpgp.readKey({ armoredKey: armor });
		const fp = key.getFingerprint?.();
		const uid = key.getUserIDs?.()?.[0];
		const msg = `Chiave OK\nFingerprint: ${fp}\nUserID: ${uid || "N/D"}`;
		await storeValue("txt_info_key", `✅ ${msg}`);
		showAlert(msg, "success");
		return { fingerprint: fp, userID: uid, armored: armor };
	},

	/* ============ Cifratura ============ */
	/**
   * filePicker: FilePicker del documento (es. FilePickerFile)
   * keyPicker:  FilePicker della chiave pubblica .asc (es. FilePickerPubKey)
   * asciiArmor: true => .asc (testo), false => .pgp (binario)
   */
	async cifraDaPicker(filePicker, keyPicker, asciiArmor = true) {
		// 1) File
		const fileObj = this._getFileFromPicker(filePicker);
		const fileSrc = fileObj.data || fileObj.dataURL;
		if (!fileSrc) throw new Error("File da cifrare non valido.");
		const fileBytes = this._b64ToBytes(fileSrc);

		// 2) Chiave pubblica (estrazione + parse)
		let armoredPub;
		try {
			armoredPub = this._armoredFromKeyPicker(keyPicker);
		} catch (e) {
			console.error("Estrazione chiave fallita:", e);
			throw e;
		}

		let encKey;
		try {
			encKey = await openpgp.readKey({ armoredKey: armoredPub });
		} catch (e) {
			const looksPriv = /-----BEGIN PGP (?:SECRET|PRIVATE) KEY BLOCK-----/i.test(armoredPub);
			if (looksPriv) {
				throw new Error("Hai caricato una PRIVATE KEY. Per cifrare serve la PUBLIC KEY del destinatario.");
			}
			const preview = armoredPub.slice(0, 80) + "..." + armoredPub.slice(-60);
			console.error("Misformed armored text:", e?.message, "\nPreview:", preview);
			throw new Error("La chiave pubblica non è valida (Misformed armored text). Riesporta la PUBLIC KEY ASCII-armored e riprova.");
		}

		// 3) Crea messaggio e cifra
		const message = await openpgp.createMessage({ binary: fileBytes });
		const encrypted = await openpgp.encrypt({
			message,
			encryptionKeys: [encKey],
			format: asciiArmor ? "armored" : "binary"   // stringa | Uint8Array
		});

		// 4) Download affidabile
		const outName = `${fileObj.name}.${asciiArmor ? "asc" : "pgp"}`;
		storeValue("txt_info_key","✅ File cifrato correttamente!");
		if (asciiArmor) {
			// stringa armor -> passala direttamente
			return download(encrypted, outName, "application/pgp-encrypted");
		} else {
			// Uint8Array -> data URL base64
			const b64 = this._uint8ToBase64(encrypted);
			const dataUrl = `data:application/pgp-encrypted;base64,${b64}`;
			return download(dataUrl, outName, "application/pgp-encrypted");
		}
	}
};
