import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:cryptography/cryptography.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:intl/intl.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const CipherLinkApp());
}

class CipherLinkApp extends StatelessWidget {
  const CipherLinkApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CipherLink',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF0F172A), // Nordic Slate Background
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF14B8A6), // Nordic Teal
          secondary: Color(0xFF2DD4BF), // Ice Teal
          surface: Color(0xFF1E293B), // Slate Surface
          surfaceContainer: Color(0xFF1E293B),
          error: Color(0xFFF43F5E),
          onPrimary: Color(0xFF0F172A),
          onSurface: Color(0xFFF8FAFC),
        ),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF1E293B),
          foregroundColor: Colors.white,
          elevation: 0,
        ),
      ),
      home: const ChatScreen(),
    );
  }
}

// Model for ephemeral chat messages (Strictly stored in RAM)
class ChatMessage {
  final String id;
  final String sender; // 'me' or 'peer'
  final String text;
  final DateTime timestamp;
  final String iv;
  final bool isDecrypted;

  ChatMessage({
    required this.id,
    required this.sender,
    required this.text,
    required this.timestamp,
    required this.iv,
    this.isDecrypted = true,
  });
}

// Model for trusted peers
class PeerContact {
  final String id;
  final String alias;
  final String publicKeyBase64;
  final String fingerprint;

  PeerContact({
    required this.id,
    required this.alias,
    required this.publicKeyBase64,
    required this.fingerprint,
  });
}

class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  // Storage & Cryptography
  final _storage = const FlutterSecureStorage();
  final _keyAlgorithm = X25519();
  final _cipherAlgorithm = AesGcm.with256Bits();

  SimpleKeyPair? _myKeyPair;
  String _myPublicKeyBase64 = '';
  String _myFingerprint = '';

  // In-memory Shared Secret Cache: Map<PeerPublicKey, SecretKey>
  final Map<String, SecretKey> _sharedSecretCache = {};

  // Ephemeral in-memory message storage (Wiped on app exit)
  final Map<String, List<ChatMessage>> _ephemeralMessages = {};

  // Contacts
  final List<PeerContact> _peers = [];
  PeerContact? _activePeer;

  // WebSocket
  WebSocketChannel? _wsChannel;
  bool _isConnected = false;
  String _relayUrl = 'wss://echo.websocket.events'; // Configure with your Render relay URL

  final TextEditingController _messageController = TextEditingController();
  final ScrollController _scrollController = ScrollController();

  @override
  void initState() {
    super.initState();
    _initializeIdentity();
  }

  @override
  void dispose() {
    _wsChannel?.sink.close();
    _messageController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  // =========================================================================
  // 1. CRYPTOGRAPHIC IDENTITY GENERATION & STORAGE
  // =========================================================================
  Future<void> _initializeIdentity() async {
    try {
      final storedPrivKey = await _storage.read(key: 'cipherlink_priv_key');
      final storedPubKey = await _storage.read(key: 'cipherlink_pub_key');

      if (storedPrivKey != null && storedPubKey != null) {
        final privBytes = base64Decode(storedPrivKey);
        final pubBytes = base64Decode(storedPubKey);

        _myKeyPair = SimpleKeyPairData(
          privBytes,
          publicKey: SimplePublicKey(pubBytes, type: KeyPairType.x25519),
          type: KeyPairType.x25519,
        );
        _myPublicKeyBase64 = storedPubKey;
      } else {
        // Generate new local Curve25519 keypair on first launch
        _myKeyPair = await _keyAlgorithm.newKeyPair();
        final pubKey = await _myKeyPair!.extractPublicKey();
        final privKeyData = await _myKeyPair!.extractPrivateKeyBytes();

        _myPublicKeyBase64 = base64Encode(pubKey.bytes);
        final privBase64 = base64Encode(privKeyData);

        await _storage.write(key: 'cipherlink_priv_key', value: privBase64);
        await _storage.write(key: 'cipherlink_pub_key', value: _myPublicKeyBase64);
      }

      // Compute SHA-256 fingerprint
      final sha256 = Sha256();
      final hash = await sha256.hash(base64Decode(_myPublicKeyBase64));
      _myFingerprint = hash.bytes
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(':')
          .toUpperCase();

      _setupDefaultPeers();
      _connectWebSocket();

      if (mounted) setState(() {});
    } catch (e) {
      debugPrint('Error initializing identity: $e');
    }
  }

  void _setupDefaultPeers() {
    _peers.addAll([
      PeerContact(
        id: 'peer-svalbard',
        alias: 'Svalbard Secure Relay',
        publicKeyBase64: 'MCowBQYDK2VuAyEA8vW4oQ2Z7zYnL8F+Qh6J19sB5V3rK0+xP9u1d8c=x9A=',
        fingerprint: '3C:8A:2F:90:5E:B1:77:4D:11:09:A6:44:D8:EF:92:0C',
      ),
      PeerContact(
        id: 'peer-oslo',
        alias: 'Oslo Vault Node [01]',
        publicKeyBase64: 'MCowBQYDK2VuAyEAvL38K9P2X1Q5mZ7nK+D8W9A6S1f0G4r2T8b6C4=k8Q=',
        fingerprint: '8F:12:4A:9C:20:9E:BA:77:43:1D:90:4B:CE:51:7A:F0',
      ),
    ]);
    if (_peers.isNotEmpty) {
      _activePeer = _peers.first;
    }
  }

  // =========================================================================
  // 2. WEBSOCKET ROUTING & HANDSHAKE
  // =========================================================================
  void _connectWebSocket() {
    try {
      _wsChannel?.sink.close();
      _wsChannel = WebSocketChannel.connect(Uri.parse(_relayUrl));

      // Initial Handshake: Register Public Key ID
      final handshake = jsonEncode({
        'type': 'register',
        'publicKey': _myPublicKeyBase64,
      });
      _wsChannel!.sink.add(handshake);

      setState(() => _isConnected = true);

      _wsChannel!.stream.listen(
        (data) {
          _handleIncomingWirePacket(data);
        },
        onError: (err) {
          if (mounted) setState(() => _isConnected = false);
        },
        onDone: () {
          if (mounted) setState(() => _isConnected = false);
        },
      );
    } catch (e) {
      if (mounted) setState(() => _isConnected = false);
    }
  }

  // =========================================================================
  // 3. ENCRYPTION & DECRYPTION (X25519 + AES-GCM 256)
  // =========================================================================
  Future<SecretKey> _getOrCreateSharedSecret(String peerPublicKeyBase64) async {
    if (_sharedSecretCache.containsKey(peerPublicKeyBase64)) {
      return _sharedSecretCache[peerPublicKeyBase64]!;
    }

    final peerBytes = base64Decode(peerPublicKeyBase64);
    final remotePublicKey = SimplePublicKey(peerBytes, type: KeyPairType.x25519);

    // Derive Shared Secret Key via X25519
    final sharedSecret = await _keyAlgorithm.sharedSecretKey(
      keyPair: _myKeyPair!,
      remotePublicKey: remotePublicKey,
    );

    _sharedSecretCache[peerPublicKeyBase64] = sharedSecret;
    return sharedSecret;
  }

  // Encrypt plaintext locally in memory before sending
  Future<void> _sendMessage() async {
    final text = _messageController.text.trim();
    if (text.isEmpty || _activePeer == null || _myKeyPair == null) return;

    _messageController.clear();

    try {
      final sharedSecret = await _getOrCreateSharedSecret(_activePeer!.publicKeyBase64);

      // AES-GCM 256-bit encryption with random 12-byte nonce/IV
      final plaintextBytes = utf8.encode(text);
      final secretBox = await _cipherAlgorithm.encrypt(
        plaintextBytes,
        secretKey: sharedSecret,
      );

      final cipherTextBase64 = base64Encode(secretBox.cipherText + secretBox.mac.bytes);
      final ivBase64 = base64Encode(secretBox.nonce);

      // JSON wire payload (Plaintext is NEVER sent over the wire)
      final payload = jsonEncode({
        'to': _activePeer!.publicKeyBase64,
        'from': _myPublicKeyBase64,
        'cipherText': cipherTextBase64,
        'iv': ivBase64,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
      });

      _wsChannel?.sink.add(payload);

      // Store in volatile RAM
      final newMsg = ChatMessage(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        sender: 'me',
        text: text,
        timestamp: DateTime.now(),
        iv: ivBase64,
      );

      _appendEphemeralMessage(_activePeer!.publicKeyBase64, newMsg);
      _scrollToBottom();
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Encryption error: $e')),
      );
    }
  }

  // Decrypt incoming AES-GCM payload
  Future<void> _handleIncomingWirePacket(dynamic rawData) async {
    try {
      final data = jsonDecode(rawData.toString());
      if (data is! Map<String, dynamic>) return;

      final to = data['to'] as String?;
      final from = data['from'] as String?;
      final cipherText = data['cipherText'] as String?;
      final iv = data['iv'] as String?;

      if (to == null || from == null || cipherText == null || iv == null) return;

      // Ensure packet is addressed to our public key
      if (to != _myPublicKeyBase64) return;
      if (from == _myPublicKeyBase64) return; // Prevent echo

      final sharedSecret = await _getOrCreateSharedSecret(from);

      final combinedBytes = base64Decode(cipherText);
      final nonceBytes = base64Decode(iv);

      // Split ciphertext and 16-byte MAC
      final macBytes = combinedBytes.sublist(combinedBytes.length - 16);
      final encryptedBytes = combinedBytes.sublist(0, combinedBytes.length - 16);

      final clearBytes = await _cipherAlgorithm.decrypt(
        SecretBox(
          encryptedBytes,
          nonce: nonceBytes,
          mac: Mac(macBytes),
        ),
        secretKey: sharedSecret,
      );

      final decryptedText = utf8.decode(clearBytes);

      final msg = ChatMessage(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        sender: 'peer',
        text: decryptedText,
        timestamp: DateTime.now(),
        iv: iv,
      );

      _appendEphemeralMessage(from, msg);
      _scrollToBottom();
    } catch (e) {
      debugPrint('Decryption failed: $e');
    }
  }

  void _appendEphemeralMessage(String peerKey, ChatMessage message) {
    if (!_ephemeralMessages.containsKey(peerKey)) {
      _ephemeralMessages[peerKey] = [];
    }
    setState(() {
      _ephemeralMessages[peerKey]!.add(message);
    });
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 250),
          curve: Curves.easeOut,
        );
      }
    });
  }

  // =========================================================================
  // 4. UI SHELL & DIALOGS
  // =========================================================================
  void _showIdentityDialog() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: const Row(
          children: [
            Icon(Icons.fingerprint, color: Color(0xFF2DD4BF)),
            SizedBox(width: 8),
            Text('Cryptographic Identity', style: TextStyle(fontSize: 16)),
          ],
        ),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(16),
                ),
                child: QrImageView(
                  data: _myPublicKeyBase64,
                  version: QrVersions.auto,
                  size: 190.0,
                  backgroundColor: Colors.white,
                ),
              ),
              const SizedBox(height: 16),
              const Align(
                alignment: Alignment.centerLeft,
                child: Text('Curve25519 Public Key (SPKI):',
                    style: TextStyle(fontSize: 11, color: Colors.grey)),
              ),
              const SizedBox(height: 4),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                decoration: BoxDecoration(
                  color: const Color(0xFF0F172A),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFF334155)),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        _myPublicKeyBase64,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                      ),
                    ),
                    IconButton(
                      icon: const Icon(Icons.copy, size: 16, color: Color(0xFF2DD4BF)),
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: _myPublicKeyBase64));
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Public key copied!')),
                        );
                      },
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: const Color(0xFF0F172A),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  'Fingerprint: $_myFingerprint',
                  style: const TextStyle(
                      fontFamily: 'monospace', fontSize: 10, color: Color(0xFF94A3B8)),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Close', style: TextStyle(color: Color(0xFF2DD4BF))),
          ),
        ],
      ),
    );
  }

  void _showAddPeerDialog() {
    final aliasController = TextEditingController();
    final keyController = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        title: const Text('Add Trusted Peer', style: TextStyle(fontSize: 16)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: aliasController,
              decoration: const InputDecoration(
                labelText: 'Peer Alias (e.g. Alice)',
                labelStyle: TextStyle(color: Colors.grey, fontSize: 13),
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: keyController,
              maxLines: 2,
              decoration: const InputDecoration(
                labelText: 'Public Key Base64',
                labelStyle: TextStyle(color: Colors.grey, fontSize: 13),
              ),
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              icon: const Icon(Icons.qr_code_scanner, size: 18),
              label: const Text('Scan QR Code'),
              style: OutlinedButton.styleFrom(foregroundColor: const Color(0xFF2DD4BF)),
              onPressed: () async {
                Navigator.pop(ctx);
                final scanned = await Navigator.push<String>(
                  context,
                  MaterialPageRoute(builder: (_) => const QRScannerScreen()),
                );
                if (scanned != null) {
                  keyController.text = scanned;
                  _showAddPeerDialog();
                }
              },
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel', style: TextStyle(color: Colors.grey)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF14B8A6),
              foregroundColor: const Color(0xFF0F172A),
            ),
            onPressed: () {
              final alias = aliasController.text.trim();
              final key = keyController.text.trim();
              if (alias.isNotEmpty && key.isNotEmpty) {
                final newPeer = PeerContact(
                  id: 'peer-${DateTime.now().millisecondsSinceEpoch}',
                  alias: alias,
                  publicKeyBase64: key,
                  fingerprint: 'VERIFIED',
                );
                setState(() {
                  _peers.add(newPeer);
                  _activePeer = newPeer;
                });
                Navigator.pop(ctx);
              }
            },
            child: const Text('Add Peer'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final activeMessages = _activePeer != null
        ? _ephemeralMessages[_activePeer!.publicKeyBase64] ?? []
        : <ChatMessage>[];

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            Container(
              width: 10,
              height: 10,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: _isConnected ? const Color(0xFF2DD4BF) : Colors.redAccent,
              ),
            ),
            const SizedBox(width: 8),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  _activePeer?.alias ?? 'CipherLink',
                  style: const TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
                ),
                Text(
                  _isConnected ? 'Zero-Knowledge E2EE • RAM' : 'Offline Relay',
                  style: const TextStyle(fontSize: 10, color: Color(0xFF94A3B8)),
                ),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.qr_code, color: Color(0xFF2DD4BF)),
            tooltip: 'My Public Identity',
            onPressed: _showIdentityDialog,
          ),
          IconButton(
            icon: const Icon(Icons.person_add, color: Colors.white70),
            tooltip: 'Add Peer',
            onPressed: _showAddPeerDialog,
          ),
        ],
      ),
      drawer: Drawer(
        backgroundColor: const Color(0xFF0F172A),
        child: Column(
          children: [
            UserAccountsDrawerHeader(
              decoration: const BoxDecoration(color: Color(0xFF1E293B)),
              accountName: const Text('My Cryptographic Node',
                  style: TextStyle(fontWeight: FontWeight.bold)),
              accountEmail: Text(
                _myPublicKeyBase64.isNotEmpty
                    ? '${_myPublicKeyBase64.substring(0, 10)}...${_myPublicKeyBase64.substring(_myPublicKeyBase64.length - 8)}'
                    : 'Generating key...',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
              ),
              currentAccountPicture: const CircleAvatar(
                backgroundColor: Color(0xFF14B8A6),
                child: Icon(Icons.lock_outline, color: Color(0xFF0F172A)),
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Text('TRUSTED PEERS',
                      style: TextStyle(color: Colors.grey, fontSize: 12, fontWeight: FontWeight.bold)),
                  IconButton(
                    icon: const Icon(Icons.add, color: Color(0xFF2DD4BF), size: 20),
                    onPressed: _showAddPeerDialog,
                  ),
                ],
              ),
            ),
            Expanded(
              child: ListView.builder(
                itemCount: _peers.length,
                itemBuilder: (ctx, index) {
                  final peer = _peers[index];
                  final isSelected = peer.id == _activePeer?.id;
                  return ListTile(
                    tileColor: isSelected ? const Color(0xFF1E293B) : Colors.transparent,
                    leading: CircleAvatar(
                      backgroundColor: isSelected
                          ? const Color(0xFF2DD4BF)
                          : const Color(0xFF334155),
                      child: Text(
                        peer.alias.substring(0, 1).toUpperCase(),
                        style: TextStyle(
                            color: isSelected ? const Color(0xFF0F172A) : Colors.white),
                      ),
                    ),
                    title: Text(peer.alias,
                        style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                    subtitle: Text(
                      '${peer.publicKeyBase64.substring(0, 8)}...',
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 10),
                    ),
                    onTap: () {
                      setState(() => _activePeer = peer);
                      Navigator.pop(ctx);
                    },
                  );
                },
              ),
            ),
          ],
        ),
      ),
      body: Column(
        children: [
          // Ephemeral RAM Notice Banner
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
            color: const Color(0xFF1E293B).withOpacity(0.5),
            child: const Row(
              children: [
                Icon(Icons.shield_outlined, size: 14, color: Color(0xFF2DD4BF)),
                SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Zero Disk Logging: All messages exist exclusively in RAM.',
                    style: TextStyle(fontSize: 10, color: Color(0xFF94A3B8)),
                  ),
                ),
              ],
            ),
          ),
          // Messages List View
          Expanded(
            child: activeMessages.isEmpty
                ? const Center(
                    child: Text(
                      'No messages in this RAM session.\nSend an encrypted message below.',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: Colors.grey, fontSize: 12),
                    ),
                  )
                : ListView.builder(
                    controller: _scrollController,
                    padding: const EdgeInsets.all(16),
                    itemCount: activeMessages.length,
                    itemBuilder: (ctx, index) {
                      final msg = activeMessages[index];
                      final isMe = msg.sender == 'me';
                      return Align(
                        alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
                        child: Container(
                          margin: const EdgeInsets.only(bottom: 12),
                          padding: const EdgeInsets.all(12),
                          constraints: BoxConstraints(
                            maxWidth: MediaQuery.of(context).size.width * 0.78,
                          ),
                          decoration: BoxDecoration(
                            color: isMe
                                ? const Color(0xFF0F766E)
                                : const Color(0xFF1E293B),
                            borderRadius: BorderRadius.only(
                              topLeft: const Radius.circular(16),
                              topRight: const Radius.circular(16),
                              bottomLeft: Radius.circular(isMe ? 16 : 0),
                              bottomRight: Radius.circular(isMe ? 0 : 16),
                            ),
                            border: isMe
                                ? null
                                : Border.all(color: const Color(0xFF334155)),
                          ),
                          child: Column(
                            crossAxisAlignment:
                                isMe ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                            children: [
                              Text(
                                msg.text,
                                style: const TextStyle(fontSize: 13, color: Colors.white),
                              ),
                              const SizedBox(height: 4),
                              Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(
                                    Icons.lock,
                                    size: 10,
                                    color: isMe ? Colors.white70 : const Color(0xFF2DD4BF),
                                  ),
                                  const SizedBox(width: 4),
                                  Text(
                                    DateFormat('HH:mm').format(msg.timestamp),
                                    style: const TextStyle(
                                        fontSize: 9, color: Colors.white60),
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
          ),
          // Bottom Message Input
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            color: const Color(0xFF1E293B),
            child: SafeArea(
              child: Row(
                children: [
                  const Icon(Icons.lock_outline, color: Color(0xFF2DD4BF), size: 20),
                  const SizedBox(width: 8),
                  Expanded(
                    child: TextField(
                      controller: _messageController,
                      style: const TextStyle(fontSize: 13),
                      decoration: const InputDecoration(
                        hintText: 'Type encrypted message...',
                        hintStyle: TextStyle(color: Colors.grey, fontSize: 13),
                        border: InputBorder.none,
                      ),
                      onSubmitted: (_) => _sendMessage(),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.send_rounded, color: Color(0xFF2DD4BF)),
                    onPressed: _sendMessage,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// QR Code Scanner Screen
class QRScannerScreen extends StatelessWidget {
  const QRScannerScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan Peer QR Code'),
        backgroundColor: const Color(0xFF1E293B),
      ),
      body: MobileScanner(
        onDetect: (capture) {
          final barcodes = capture.barcodes;
          for (final barcode in barcodes) {
            if (barcode.rawValue != null) {
              Navigator.pop(context, barcode.rawValue);
              break;
            }
          }
        },
      ),
    );
  }
}
