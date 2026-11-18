package bench

// sshKexinit is an SSH-2 banner followed by a KEXINIT packet (binary packet protocol, RFC 4253 §6, §7.1).
func sshKexinit() []byte {
	lists := []string{"curve25519-sha256,ecdh-sha2-nistp256", "ssh-ed25519,rsa-sha2-512", "aes128-gcm@openssh.com,chacha20-poly1305@openssh.com",
		"aes128-gcm@openssh.com,chacha20-poly1305@openssh.com", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""}
	payload := append([]byte{20}, make([]byte, 16)...)
	for _, l := range lists {
		payload = append(payload, byte(len(l)>>24), byte(len(l)>>16), byte(len(l)>>8), byte(len(l)))
		payload = append(payload, l...)
	}
	payload = append(payload, 0, 0, 0, 0, 0)
	padding := 8 - (len(payload)+5)%8
	if padding < 4 {
		padding += 8
	}
	length := len(payload) + padding + 1
	packet := []byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length), byte(padding)}
	packet = append(append(packet, payload...), make([]byte, padding)...)
	return append([]byte("SSH-2.0-OpenSSH_9.6\r\n"), packet...)
}
