package dto

// TODO: account for file uploads
type CreateClipboardEntry struct {
	Type          string `json:"type" binding:"required"`
	Content       string `json:"content" binding:"required"`
	Encrypted     bool   `json:"encrypted"`
	EncryptionKey string `json:"encryption_key" binding:"encryptionKey"`
}