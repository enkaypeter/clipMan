package dto

type UpdateClipboardEntry struct {
	Content *string `json:"content"`
	Pinned  *bool   `json:"pinned"`
	EncryptionKey string  `json:"encryption_key" binding:"encryptionKey"`
}