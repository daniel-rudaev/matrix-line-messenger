package connector

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

func (lc *LineClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	client := line.NewClient(lc.AccessToken)
	portalMid := string(msg.Portal.ID)
	fromMid := lc.midOrFallback()

	lowerPortalID := strings.ToLower(portalMid)
	isGroup := strings.HasPrefix(lowerPortalID, "c") || strings.HasPrefix(lowerPortalID, "r")

	// Determine whether we need to send as plain text (peer/group has Letter Sealing off).
	plainText := false
	if lc.E2EE == nil {
		plainText = true
		lc.UserLogin.Bridge.Log.Warn().Msg("E2EE not initialized, sending as plain text")
	} else if isGroup {
		if lc.isGroupNoE2EE(portalMid) {
			plainText = true
		}
	} else {
		// 1:1 — probe peer key to determine E2EE support
		_, _, errPeer := lc.ensurePeerKey(ctx, portalMid)
		if errPeer != nil && line.IsNoUsableE2EEPublicKey(errPeer) {
			plainText = true
		} else if errPeer != nil {
			return nil, fmt.Errorf("failed to get peer key: %w", errPeer)
		}
	}

	var chunks []string
	var err error
	contentType := int(ContentText)
	contentMetadata := map[string]string{}
	if !plainText {
		contentMetadata["e2eeVersion"] = "2"
	}

	// For plain text, we set lineMsg.Text directly; payload is used only for E2EE.
	var payload []byte
	var plainTextBody string // used when plainText == true for text messages

	switch msg.Content.MsgType {
	case event.MsgText:
		contentType = int(ContentText)
		if plainText {
			plainTextBody = msg.Content.Body
		} else {
			payload, err = json.Marshal(map[string]string{"text": msg.Content.Body})
			if err != nil {
				return nil, fmt.Errorf("failed to marshal text payload: %w", err)
			}
		}

	case event.MsgImage:
		data, err := lc.UserLogin.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, msg.Content.File)
		if err != nil {
			return nil, fmt.Errorf("failed to download media from matrix: %w", err)
		}

		mimeType := msg.Content.Info.MimeType
		isGif := mimeType == "image/gif"
		isAnimated := isGif && isAnimatedGif(data)

		extension := "jpg"
		if isGif {
			extension = "gif"
		} else if mimeType == "image/png" {
			extension = "png"
		}

		var uploadData []byte
		var keyMaterialB64 string

		if plainText {
			// Upload raw (unencrypted) data
			uploadData = data
		} else {
			uploadData, keyMaterialB64, err = lc.encryptFileData(data)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt image data: %w", err)
			}
		}

		oid, err := client.UploadOBS(uploadData)
		if err != nil {
			return nil, fmt.Errorf("failed to upload image to OBS: %w", err)
		}

		thumbnailData, thumbWidth, thumbHeight, err := generateThumbnail(data)
		if err != nil {
			lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to generate thumbnail, continuing without it")
		} else {
			var thumbToUpload []byte
			if plainText {
				thumbToUpload = thumbnailData
			} else {
				keyMaterial, _ := base64.StdEncoding.DecodeString(keyMaterialB64)

				kdf := hkdf.New(sha256.New, keyMaterial, nil, []byte("FileEncryption"))
				derived := make([]byte, 76)
				io.ReadFull(kdf, derived)

				encKey := derived[0:32]
				macKey := derived[32:64]
				nonce := derived[64:76]

				counter := make([]byte, 16)
				copy(counter, nonce)

				block, _ := aes.NewCipher(encKey)
				stream := cipher.NewCTR(block, counter)

				encryptedThumb := make([]byte, len(thumbnailData))
				stream.XORKeyStream(encryptedThumb, thumbnailData)

				h := hmac.New(sha256.New, macKey)
				h.Write(encryptedThumb)
				thumbToUpload = append(encryptedThumb, h.Sum(nil)...)
			}

			previewOID := fmt.Sprintf("%s__ud-preview", oid)
			if err := client.UploadOBSWithOID(thumbToUpload, previewOID); err != nil {
				lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to upload preview, continuing without it")
			} else {
				mediaThumbInfo := map[string]interface{}{
					"width":  thumbWidth,
					"height": thumbHeight,
				}
				if thumbInfoJSON, err := json.Marshal(mediaThumbInfo); err == nil {
					contentMetadata["MEDIA_THUMB_INFO"] = string(thumbInfoJSON)
				}

				lc.UserLogin.Bridge.Log.Info().
					Str("preview_oid", previewOID).
					Int("thumb_size", len(thumbnailData)).
					Int("thumb_width", thumbWidth).
					Int("thumb_height", thumbHeight).
					Msg("Uploaded preview thumbnail")
			}
		}

		contentType = int(ContentImage)
		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "emi"
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(uploadData))
		contentMetadata["contentType"] = fmt.Sprintf("%d", ContentImage)

		if !plainText {
			contentMetadata["ENC_KM"] = keyMaterialB64
		}

		fileName := msg.Content.Body
		if fileName == "" {
			if isGif {
				fileName = "animation.gif"
			} else {
				fileName = "image.jpg"
			}
		}
		contentMetadata["FILE_NAME"] = fileName

		mediaContentInfo := map[string]interface{}{
			"category":  "original",
			"fileSize":  len(uploadData),
			"extension": extension,
		}
		if isAnimated {
			mediaContentInfo["animated"] = true
		}
		if mediaInfoJSON, err := json.Marshal(mediaContentInfo); err == nil {
			contentMetadata["MEDIA_CONTENT_INFO"] = string(mediaInfoJSON)
		}

		payload = []byte("{}")

	case event.MsgFile:
		data, err := lc.UserLogin.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, msg.Content.File)
		if err != nil {
			return nil, fmt.Errorf("failed to download file from matrix: %w", err)
		}

		var uploadData []byte
		var keyMaterialB64 string

		if plainText {
			uploadData = data
		} else {
			uploadData, keyMaterialB64, err = lc.encryptFileData(data)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt file data: %w", err)
			}
		}

		oid, err := client.UploadOBSWithSID(uploadData, "emf")
		if err != nil {
			return nil, fmt.Errorf("failed to upload file to OBS: %w", err)
		}

		contentType = int(ContentFile)
		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "emf"
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data))
		contentMetadata["contentType"] = fmt.Sprintf("%d", ContentFile)

		fileName := msg.Content.Body
		if fileName == "" {
			fileName = "file.bin"
		}
		contentMetadata["FILE_NAME"] = fileName

		if plainText {
			payload = []byte("{}")
		} else {
			filePayload := map[string]string{
				"keyMaterial": keyMaterialB64,
				"fileName":    fileName,
			}
			payloadBytes, _ := json.Marshal(filePayload)
			payload = payloadBytes
		}

		lc.UserLogin.Bridge.Log.Info().
			Str("oid", oid).
			Str("file_name", fileName).
			Bool("plain_text", plainText).
			Int("upload_size", len(uploadData)).
			Int("original_size", len(data)).
			Msg("Prepared file message")

	case event.MsgVideo:
		data, err := lc.UserLogin.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, msg.Content.File)
		if err != nil {
			return nil, fmt.Errorf("failed to download video from matrix: %w", err)
		}

		var uploadData []byte
		var keyMaterialB64 string

		if plainText {
			uploadData = data
		} else {
			uploadData, keyMaterialB64, err = lc.encryptVideoData(data)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt video data: %w", err)
			}
		}

		oid, err := client.UploadOBSWithSID(uploadData, "emv")
		if err != nil {
			return nil, fmt.Errorf("failed to upload video to OBS: %w", err)
		}

		if !plainText {
			chunkHashes := generateChunkHashes(uploadData[:len(uploadData)-32])
			if len(chunkHashes) > 0 {
				hashOID := fmt.Sprintf("%s__ud-hash", oid)
				if err := client.UploadOBSWithOIDAndSID(chunkHashes, hashOID, "emv"); err != nil {
					lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to upload video hash, continuing without it")
				} else {
					lc.UserLogin.Bridge.Log.Info().
						Str("hash_oid", hashOID).
						Int("hash_size", len(chunkHashes)).
						Msg("Uploaded video chunk hashes")
				}
			}
		}

		thumbnailData, thumbWidth, thumbHeight, err := extractVideoThumbnail(data)
		if err != nil {
			lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to extract video thumbnail, using placeholder")
			thumbWidth = 384
			thumbHeight = 384
			placeholderImg := image.NewRGBA(image.Rect(0, 0, thumbWidth, thumbHeight))
			var thumbBuf bytes.Buffer
			jpeg.Encode(&thumbBuf, placeholderImg, &jpeg.Options{Quality: 30})
			thumbnailData = thumbBuf.Bytes()
		}

		if len(thumbnailData) > 0 {
			var thumbToUpload []byte
			if plainText {
				thumbToUpload = thumbnailData
			} else {
				keyMaterial, _ := base64.StdEncoding.DecodeString(keyMaterialB64)
				kdf := hkdf.New(sha256.New, keyMaterial, nil, []byte("FileEncryption"))
				derived := make([]byte, 76)
				io.ReadFull(kdf, derived)

				encKey := derived[0:32]
				macKey := derived[32:64]
				nonce := derived[64:76]

				counter := make([]byte, 16)
				copy(counter, nonce)

				block, _ := aes.NewCipher(encKey)
				stream := cipher.NewCTR(block, counter)

				encryptedThumb := make([]byte, len(thumbnailData))
				stream.XORKeyStream(encryptedThumb, thumbnailData)

				h := hmac.New(sha256.New, macKey)
				h.Write(encryptedThumb)
				thumbToUpload = append(encryptedThumb, h.Sum(nil)...)
			}

			previewOID := fmt.Sprintf("%s__ud-preview", oid)
			if err := client.UploadOBSWithOIDAndSID(thumbToUpload, previewOID, "emv"); err != nil {
				lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to upload video preview, continuing without it")
			} else {
				mediaThumbInfo := map[string]interface{}{
					"width":  thumbWidth,
					"height": thumbHeight,
				}
				if thumbInfoJSON, err := json.Marshal(mediaThumbInfo); err == nil {
					contentMetadata["MEDIA_THUMB_INFO"] = string(thumbInfoJSON)
				}

				lc.UserLogin.Bridge.Log.Info().
					Str("preview_oid", previewOID).
					Int("preview_size", len(thumbToUpload)).
					Int("thumb_width", thumbWidth).
					Int("thumb_height", thumbHeight).
					Msg("Uploaded video preview placeholder")
			}
		}

		contentType = int(ContentVideo)
		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "emv"
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data))
		contentMetadata["contentType"] = fmt.Sprintf("%d", ContentVideo)

		if !plainText {
			contentMetadata["ENC_KM"] = keyMaterialB64
		}

		if msg.Content.Info.Duration > 0 {
			contentMetadata["DURATION"] = fmt.Sprintf("%d", msg.Content.Info.Duration)
		}

		payload = []byte("{}")

		lc.UserLogin.Bridge.Log.Info().
			Str("oid", oid).
			Bool("plain_text", plainText).
			Int("upload_size", len(uploadData)).
			Msg("Prepared video message")

	default:
		return nil, fmt.Errorf("message type %s not implemented", msg.Content.MsgType)
	}

	// Encryption phase — skip entirely for plain text
	if !plainText {
		if isGroup {
			if errFetch := lc.fetchAndUnwrapGroupKey(ctx, portalMid, 0); errFetch != nil {
				lc.UserLogin.Bridge.Log.Debug().Err(errFetch).Str("chat_mid", portalMid).Msg("fetchAndUnwrapGroupKey before encrypt failed")
			}
			if contentType != int(ContentText) {
				chunks, err = lc.E2EE.EncryptGroupMessageRaw(portalMid, fromMid, contentType, payload)
			} else {
				chunks, err = lc.E2EE.EncryptGroupMessage(portalMid, fromMid, msg.Content.Body)
			}
			if err != nil {
				if errFetch := lc.fetchAndUnwrapGroupKey(ctx, portalMid, 0); errFetch == nil {
					if contentType != int(ContentText) {
						chunks, err = lc.E2EE.EncryptGroupMessageRaw(portalMid, fromMid, contentType, payload)
					} else {
						chunks, err = lc.E2EE.EncryptGroupMessage(portalMid, fromMid, msg.Content.Body)
					}
				} else if line.IsNoUsableE2EEGroupKey(errFetch) || line.IsNoUsableE2EEGroupKey(err) {
					// Group has no E2EE keys — fall back to plain text
					lc.markGroupNoE2EE(portalMid)
					lc.UserLogin.Bridge.Log.Info().Str("chat_mid", portalMid).Msg("Group has no E2EE keys, falling back to plain text")
					plainText = true
					chunks = nil
					err = nil
					delete(contentMetadata, "e2eeVersion")
					if contentType == int(ContentText) {
						plainTextBody = msg.Content.Body
					}
				}
			}
		} else {
			// 1-1 Encryption (peer key already fetched above)
			myRaw, myKeyID, errKey := lc.E2EE.MyKeyIDs()
			if errKey != nil {
				return nil, fmt.Errorf("missing own E2EE key: %w", errKey)
			}
			peerRaw, peerPub, errPeer := lc.ensurePeerKey(ctx, portalMid)
			if errPeer != nil {
				return nil, fmt.Errorf("failed to get peer key: %w", errPeer)
			}

			chunks, err = lc.E2EE.EncryptMessageV2Raw(portalMid, fromMid, myKeyID, peerPub, myRaw, peerRaw, contentType, payload)
		}

		if err != nil {
			return nil, fmt.Errorf("encrypt failed: %w", err)
		}
	}

	if plainText {
		lc.UserLogin.Bridge.Log.Info().Str("portal", portalMid).Int("content_type", contentType).Msg("Sending plain text message (no E2EE)")
	}

	now := time.Now().UnixMilli()
	lineMsg := &line.Message{
		ID:              fmt.Sprintf("local-%d", now),
		From:            lc.midOrFallback(),
		To:              portalMid,
		ToType:          int(guessToType(portalMid)),
		SessionID:       0,
		CreatedTime:     json.Number(strconv.FormatInt(now, 10)),
		ContentType:     contentType,
		HasContent:      contentType != int(ContentText),
		ContentMetadata: contentMetadata,
	}

	if plainText {
		lineMsg.Text = plainTextBody
	} else {
		lineMsg.Chunks = chunks
	}

	var relatedMsg *database.Message

	if msg.ReplyTo != nil {
		relatedMsg = msg.ReplyTo
	} else if msg.Content.RelatesTo != nil && msg.Content.RelatesTo.InReplyTo != nil {
		replyToMXID := msg.Content.RelatesTo.InReplyTo.EventID
		if replyToMXID != "" {
			dbMsg, err := lc.UserLogin.Bridge.DB.Message.GetPartByMXID(ctx, replyToMXID)
			if err == nil && dbMsg != nil {
				relatedMsg = dbMsg
			}
		}
	}

	if relatedMsg != nil && relatedMsg.ID != "" && !strings.HasPrefix(string(relatedMsg.ID), "local-") {
		lineMsg.RelatedMessageID = string(relatedMsg.ID)
		lineMsg.MessageRelationType = 3
		lineMsg.RelatedMessageServiceCode = 1
	}

	reqSeq := int(now % 1_000_000_000)
	lc.reqSeqMu.Lock()
	if lc.sentReqSeqs == nil {
		lc.sentReqSeqs = make(map[int]time.Time)
	}
	lc.sentReqSeqs[reqSeq] = time.Now()
	lc.reqSeqMu.Unlock()

	sentMsg, err := client.SendMessage(int64(reqSeq), lineMsg)
	if err != nil {
		return nil, err
	}

	return &bridgev2.MatrixMessageResponse{
		DB: &database.Message{
			ID:        networkid.MessageID(sentMsg.ID),
			SenderID:  makeUserID(string(lc.UserLogin.ID)),
			Timestamp: time.UnixMilli(now),
		},
	}, nil
}

func (lc *LineClient) HandleMatrixMessageRemove(ctx context.Context, msg *bridgev2.MatrixMessageRemove) error {
	client := line.NewClient(lc.AccessToken)

	reqSeq := int(time.Now().UnixMilli() % 1_000_000_000)
	lc.reqSeqMu.Lock()
	if lc.sentReqSeqs == nil {
		lc.sentReqSeqs = make(map[int]time.Time)
	}
	lc.sentReqSeqs[reqSeq] = time.Now()
	lc.reqSeqMu.Unlock()

	return client.UnsendMessage(int64(reqSeq), string(msg.TargetMessage.ID))
}

func (lc *LineClient) HandleMatrixLeaveRoom(ctx context.Context, portal *bridgev2.Portal) error {
	client := line.NewClient(lc.AccessToken)

	reqSeq := int(time.Now().UnixMilli() % 1_000_000_000)
	lc.reqSeqMu.Lock()
	if lc.sentReqSeqs == nil {
		lc.sentReqSeqs = make(map[int]time.Time)
	}
	lc.sentReqSeqs[reqSeq] = time.Now()
	lc.reqSeqMu.Unlock()

	return client.SendChatRemoved(int64(reqSeq), string(portal.ID), "0", 0)
}
