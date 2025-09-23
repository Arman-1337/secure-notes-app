# 🔐 Secure Notes - Client-Side Encrypted Note Sharing

[![Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://yourusername.github.io/secure-notes-app)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-success)](https://github.com/yourusername/secure-notes-app/actions)

A client-side encrypted note sharing application that demonstrates modern web cryptography best practices using the Web Crypto API. Share sensitive information securely without trusting any server with your data.

![Demo GIF](docs/screenshots/demo.gif)

## ✨ Features

- 🔒 **Client-side AES-GCM encryption** - Your data never leaves your device unencrypted
- 🔑 **PBKDF2 key derivation** - Password-based encryption with 100,000 iterations
- 🌐 **Shareable encrypted URLs** - Send notes through any communication channel
- ⚡ **Zero server storage** - Notes exist only in URL parameters
- 🛡️ **Authenticated encryption** - Detects data tampering automatically
- 📱 **Responsive design** - Works on desktop and mobile devices
- 🎨 **Dark theme UI** - Professional VS Code-inspired interface
- 📋 **One-click sharing** - Copy encrypted URLs to clipboard

## 🔍 How It Works

1. **Encryption Process**: User enters plaintext note and password → PBKDF2 derives AES key from password + random salt → AES-GCM encrypts note with random IV → Combined salt+IV+ciphertext encoded in shareable URL
2. **Sharing**: Encrypted URL can be shared through any medium (email, chat, etc.)
3. **Decryption Process**: Recipient opens URL → Enters password → Same PBKDF2 process derives key → AES-GCM decrypts and authenticates data → Plaintext displayed

**Technical Stack**: Vanilla JavaScript, Web Crypto API, AES-GCM 256-bit, PBKDF2-SHA256

## 🛡️ Security Model

### What This Protects Against:
- ✅ **Server-side data breaches** - No plaintext stored on servers
- ✅ **Man-in-the-middle attacks** - End-to-end encryption
- ✅ **Data tampering** - AES-GCM authenticated encryption
- ✅ **Rainbow table attacks** - Unique salt per encryption
- ✅ **Brute force attacks** - 100,000 PBKDF2 iterations

### What This Does NOT Protect Against:
- ❌ **Weak passwords** - Use strong, unique passwords
- ❌ **Compromised devices** - Malware can capture plaintext
- ❌ **Social engineering** - Don't share passwords directly
- ❌ **Browser vulnerabilities** - Keep your browser updated
- ❌ **Screen recording** - Be aware of your environment

### Threat Model
This app is designed for sharing moderately sensitive information (passwords, personal notes, small confidential data) between trusted parties. It assumes:
- You trust your browser's Web Crypto API implementation
- Communication channels for URL/password sharing are separate
- Recipients are authorized to access the information
- Devices used for encryption/decryption are not compromised

**Not suitable for**: Highly classified information, long-term storage, or scenarios requiring perfect forward secrecy.

## 🚀 Quick Start

### Run Locally
```bash
# Clone the repository
git clone https://github.com/yourusername/secure-notes-app.git
cd secure-notes-app

# Install dependencies (for testing)
npm install

# Open in browser
open index.html
# OR serve with local server (recommended)
python -m http.server 8000
# Then visit: http://localhost:8000
```

### Deploy to GitHub Pages
1. Fork this repository
2. Go to Settings > Pages
3. Select "Deploy from a branch"
4. Choose "main" branch and "/ (root)"
5. Your app will be live at `https://arman-1337.github.io/secure-notes-app/`

### Deploy to Vercel
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fyourusername%2Fsecure-notes-app)

## 🧪 Testing

```bash
# Run unit tests
npm test

# Run tests with coverage
npm run test:coverage

# Run security tests
npm run test:security
```

### Manual Security Testing
1. **Encryption Test**: Create note "Hello World" with password "test123" → Should generate unique URLs each time
2. **Wrong Password Test**: Try decrypting with incorrect password → Should fail gracefully
3. **Tampering Test**: Modify encrypted URL hash → Should detect corruption

## 📸 Screenshots

### Encryption Interface
![Encrypt Screen](docs/screenshots/encrypt-screen.png)

### Decryption Interface  
![Decrypt Screen](docs/screenshots/decrypt-screen.png)

## 🔧 Configuration

Key security parameters (in `src/crypto-utils.js`):
```javascript
const PBKDF2_ITERATIONS = 100000; // OWASP recommended minimum
const SALT_LENGTH = 16;            // 128 bits
const IV_LENGTH = 12;              // 96 bits for AES-GCM
const KEY_LENGTH = 256;            // 256-bit AES key
```

## 🚧 Roadmap

### Phase 2 (Advanced Features)
- [ ] File encryption support (images, documents)
- [ ] Expiration dates for shared notes
- [ ] Multiple recipient support with key sharing
- [ ] Browser extension for easy note creation

### Phase 3 (Enterprise Features)
- [ ] Digital signatures for authenticity
- [ ] Audit logs for access tracking
- [ ] Integration with password managers
- [ ] Mobile app with QR code sharing

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Security Issues
Please report security vulnerabilities to [SECURITY.md](docs/SECURITY.md). Do not open public issues for security bugs.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 Learning Outcomes

This project demonstrates:
- Modern cryptography implementation with Web Crypto API
- Secure key derivation and password handling
- Client-side security architecture design
- Professional JavaScript development practices
- Security-first user experience design

## 🙏 Acknowledgments

- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) documentation
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- Security research from the cryptography community

---

**⚠️ Security Notice**: This is a demonstration project. While it implements strong cryptography, please evaluate your specific security requirements before using for highly sensitive data.
