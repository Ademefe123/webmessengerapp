const express = require('express');
const app = express();
const server = require('http').createServer(app);
const io = require('socket.io')(server);
const fs = require('fs');
const bcrypt = require('bcryptjs');
const path = require('path');
const os = require('os');
const cors = require('cors');
const multer = require('multer');

const port = process.env.PORT || 3000;

// Dosya yolları
const usersFile = path.join(__dirname, 'data', 'users.json');
const messagesFile = path.join(__dirname, 'data', 'messages.json');

// Data klasörünü oluştur
if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'));
}

// Dosyaları oluştur (yoksa)
if (!fs.existsSync(usersFile)) {
    fs.writeFileSync(usersFile, '[]');
}
if (!fs.existsSync(messagesFile)) {
    fs.writeFileSync(messagesFile, '[]');
}

// Verileri oku/yaz fonksiyonları
function readData(file) {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeData(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// Middleware tanımlamaları
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`, req.body);
    next();
});
app.use(express.static('public'));

// CORS ayarlarını ekleyelim
const corsOptions = {
    origin: '*', // Tüm kaynaklara izin ver (sadece geliştirme için)
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true, // Çerezlerin gönderilmesine izin ver
    optionsSuccessStatus: 204, // Tarayıcı uyumluluğu için
};
app.use(cors(corsOptions));

// Dosya yükleme için multer yapılandırması
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)){
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
    fileFilter: function(req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif|pdf|doc|docx|mp4|avi|mov|xlsx|xls|txt/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Desteklenmeyen dosya formatı!'));
    }
});

// Admin şifresi (gerçek uygulamada daha güvenli bir yöntemle saklanmalı)
const ADMIN_PASSWORD = "admin123";

// Admin login endpoint'i
app.post('/admin/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        res.json({ success: true });
    } else {
        res.json({ success: false, error: 'Hatalı şifre' });
    }
});

// Kullanıcıları listele endpoint'i
app.get('/admin/users', (req, res) => {
    const users = readData(usersFile);
    res.json(users);
});

// Sohbeti temizle endpoint'i
app.post('/admin/clear-chat', (req, res) => {
    writeData(messagesFile, []);
    res.json({ success: true });
});

// Kullanıcı silme endpoint'i
app.delete('/admin/users/:username', (req, res) => {
    try {
        const users = readData(usersFile);
        const filteredUsers = users.filter(u => u.username !== req.params.username);
        writeData(usersFile, filteredUsers);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// İki kullanıcı arasındaki sohbeti getirme endpoint'i (admin panel için)
app.get('/admin/messages/:user1/:user2', (req, res) => {
    try {
        const messages = readData(messagesFile);
        const user1 = req.params.user1.trim();
        const user2 = req.params.user2.trim();
        
        // Sıralamadan bağımsız olarak her iki yöndeki mesajları getir
        const conversation = messages.filter(msg => 
            (msg.from.trim() === user1 && msg.to.trim() === user2) ||
            (msg.from.trim() === user2 && msg.to.trim() === user1)
        );
        
        // Mesajları tarihe göre sırala
        conversation.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        console.log(`Admin: Mesajlar getirildi: ${user1} - ${user2}, Sayı: ${conversation.length}`);
        res.json(conversation);
    } catch (error) {
        console.error('Mesajları getirme hatası:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Tekil mesaj silme endpoint'i
app.delete('/admin/messages/:messageId', (req, res) => {
    try {
        const messages = readData(messagesFile);
        const updatedMessages = messages.filter(msg => msg.id !== req.params.messageId);
        writeData(messagesFile, updatedMessages);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// İki kullanıcı arasındaki tüm sohbeti silme endpoint'i
app.delete('/admin/conversations/:user1/:user2', (req, res) => {
    try {
        const messages = readData(messagesFile);
        const updatedMessages = messages.filter(msg => 
            !(msg.from === req.params.user1 && msg.to === req.params.user2) &&
            !(msg.from === req.params.user2 && msg.to === req.params.user1)
        );
        writeData(messagesFile, updatedMessages);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Kayıt olma endpoint'i
app.post('/register', async (req, res) => {
    try {
        console.log('Register request body:', req.body);

        if (!req.body.username || !req.body.password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Kullanıcı adı ve şifre gereklidir' 
            });
        }

        const users = readData(usersFile);
        if (users.find(u => u.username.toLowerCase() === req.body.username.toLowerCase())) {
            return res.status(400).json({ 
                success: false, 
                error: 'Bu kullanıcı adı zaten kullanılıyor' 
            });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        users.push({
            username: req.body.username,
            password: hashedPassword,
            originalPassword: req.body.password // Admin panel için şifreyi saklıyoruz
        });
        writeData(usersFile, users);
        res.json({ success: true });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Sunucu hatası: ' + error.message 
        });
    }
});

// Giriş yapma endpoint'i
app.post('/login', async (req, res) => {
    try {
        console.log('Login request:', req.body); // Debug için

        if (!req.body.username || !req.body.password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Kullanıcı adı ve şifre gereklidir' 
            });
        }

        const users = readData(usersFile);
        const user = users.find(u => u.username === req.body.username);
        
        if (user && await bcrypt.compare(req.body.password, user.password)) {
            res.json({ success: true });
        } else {
            res.status(401).json({ 
                success: false, 
                error: 'Geçersiz kullanıcı adı veya şifre' 
            });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Sunucu hatası' 
        });
    }
});

// Eski mesajları getirme endpoint'i
app.get('/messages', (req, res) => {
    const messages = readData(messagesFile);
    res.json(messages.slice(-50));
});

// Tüm kullanıcıları getirme endpoint'i
app.get('/users', (req, res) => {
    const users = readData(usersFile);
    // Sadece kullanıcı adlarını gönder
    res.json(users.map(user => user.username));
});

// Dosya yükleme endpoint'i
app.post('/upload', upload.single('image'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: 'Dosya yüklenemedi' });
        }

        // Dosya yolu ve tipini kontrol et
        console.log('Yüklenen dosya:', req.file); // Debug log

        res.json({ 
            success: true, 
            filename: req.file.filename,
            path: `/uploads/${req.file.filename}`,
            fileType: req.file.mimetype,
            originalName: req.file.originalname
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Kullanıcı ayarları endpoint'i
app.post('/user/settings', async (req, res) => {
    try {
        const users = readData(usersFile);
        const user = users.find(u => u.username === req.body.currentUsername);
        
        if (!user) {
            return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı' });
        }

        // Şifre değişikliği kontrolü
        if (req.body.oldPassword && req.body.newPassword) {
            const isValidPassword = await bcrypt.compare(req.body.oldPassword, user.password);
            if (!isValidPassword) {
                return res.status(400).json({ success: false, error: 'Mevcut şifre yanlış' });
            }
            user.password = await bcrypt.hash(req.body.newPassword, 10);
            user.originalPassword = req.body.newPassword;
        }

        // Kullanıcı adı değişikliği
        if (req.body.newUsername && req.body.newUsername !== user.username) {
            if (users.find(u => u.username.toLowerCase() === req.body.newUsername.toLowerCase())) {
                return res.status(400).json({ success: false, error: 'Bu kullanıcı adı zaten kullanılıyor' });
            }
            user.username = req.body.newUsername;
        }

        // Profil fotoğrafı
        if (req.body.profilePhoto) {
            user.profilePhoto = req.body.profilePhoto;
        }

        writeData(usersFile, users);
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Profil fotoğrafı yükleme endpoint'i
app.post('/user/profile-photo', upload.single('photo'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: 'Fotoğraf yüklenemedi' });
        }
        res.json({ 
            success: true, 
            path: `/uploads/${req.file.filename}`
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Uploads klasörünü statik olarak sunma
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Aktif kullanıcıları tutacak nesne
const activeUsers = new Map();

io.on('connection', (socket) => {
    let currentUser = null;

    socket.on('user_connected', async (username) => {
        currentUser = username;
        activeUsers.set(username, socket.id);
        // Tüm kullanıcıları gönder
        const users = readData(usersFile);
        io.emit('all_users', users.map(u => u.username));
        // Aktif kullanıcıları gönder
        io.emit('active_users', Array.from(activeUsers.keys()));
        console.log(`${username} bağlandı`);
    });

    socket.on('private_message', (data) => {
        try {
            const messages = readData(messagesFile);
            const newMessage = {
                id: Date.now().toString(),
                from: data.from.trim(),
                to: data.to.trim(),
                message: data.message || '',
                file: data.file,
                fileType: data.fileType,
                timestamp: new Date()
            };

            console.log('Yeni mesaj:', newMessage); // Debug log

            messages.push(newMessage);
            writeData(messagesFile, messages);

            const receiverSocket = activeUsers.get(data.to.trim());
            if (receiverSocket) {
                io.to(receiverSocket).emit('private_message', newMessage);
            }
            socket.emit('private_message', newMessage);
        } catch (error) {
            console.error('Mesaj gönderme hatası:', error);
        }
    });

    socket.on('disconnect', () => {
        if (currentUser) {
            activeUsers.delete(currentUser);
            io.emit('active_users', Array.from(activeUsers.keys()));
            console.log(`${currentUser} ayrıldı`);
        }
    });
});

// Normal kullanıcılar için mesaj getirme endpoint'i
app.get('/messages/:from/:to', (req, res) => {
    try {
        const messages = readData(messagesFile);
        const fromUser = req.params.from.trim();
        const toUser = req.params.to.trim();
        
        // Sıralamadan bağımsız olarak her iki yöndeki mesajları getir
        const conversation = messages.filter(msg => 
            (msg.from.trim() === fromUser && msg.to.trim() === toUser) ||
            (msg.from.trim() === toUser && msg.to.trim() === fromUser)
        );
        
        // Mesajları tarihe göre sırala
        conversation.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        console.log(`User: Mesajlar getirildi: ${fromUser} - ${toUser}, Sayı: ${conversation.length}`);
        res.json(conversation);
    } catch (error) {
        console.error('Mesajları getirme hatası:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Sunucu başlatma öncesi bir test route'u ekleyelim
app.get('/test', (req, res) => {
    res.json({ status: 'Server is running' });
});

// Sunucuyu başlatmadan önce IP adresini al
const networkInterfaces = os.networkInterfaces();
let localIP = 'localhost';

// Yerel IP adresini bul
Object.keys(networkInterfaces).forEach((ifname) => {
    networkInterfaces[ifname].forEach((iface) => {
        if ('IPv4' !== iface.family || iface.internal !== false) {
            return;
        }
        localIP = iface.address;
    });
});

// Public IP adresini almak için
const getPublicIP = async () => {
    try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        return data.ip;
    } catch (error) {
        return 'Unable to get public IP';
    }
};

server.listen(port, '0.0.0.0', async () => {
    const publicIP = await getPublicIP();
    console.log(`\nSunucu çalışıyor:`);
    console.log(`- Yerel erişim: http://localhost:${port}`);
    console.log(`- Yerel ağ erişimi: http://${localIP}:${port}`);
    console.log(`- Dış ağ erişimi: http://${publicIP}:${port}`);
    console.log('\nDış ağdan erişim için:');
    console.log('1. Modem/Router ayarlarından port yönlendirme yapın:');
    console.log(`   Dış Port: ${port} -> İç IP: ${localIP} -> İç Port: ${port}`);
    console.log('2. Güvenlik duvarında gerekli izinleri verin');
    console.log('\nJSON dosyaları:');
    console.log(`- Kullanıcılar: ${usersFile}`);
    console.log(`- Mesajlar: ${messagesFile}`);
});
