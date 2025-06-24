const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin SDK
const serviceAccount = {
  "type": "service_account",
  "project_id": "kjjrjjfn",
  "private_key_id": process.env.FIREBASE_PRIVATE_KEY_ID,
  "private_key": process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  "client_email": process.env.FIREBASE_CLIENT_EMAIL,
  "client_id": process.env.FIREBASE_CLIENT_ID,
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": process.env.FIREBASE_CLIENT_CERT_URL,
  "universe_domain": "googleapis.com"
};

// Initialize Firebase only if not already initialized
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

// Helper function to generate custom token
const generateCustomToken = async (uid) => {
  try {
    const customToken = await admin.auth().createCustomToken(uid);
    return customToken;
  } catch (error) {
    console.error('Error creating custom token:', error);
    throw error;
  }
};

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ message: 'Baynana Auth Server is running!' });
});

// Register new user
app.post('/registerUser', async (req, res) => {
  try {
    const { username, password, displayName } = req.body;

    if (!username || !password || !displayName) {
      return res.status(400).json({ error: 'يرجى ملء جميع الحقول' });
    }

    // Check if username already exists
    const usernameDoc = await db.collection('usernames').doc(username.toLowerCase()).get();
    if (usernameDoc.exists) {
      return res.status(400).json({ error: 'اسم المستخدم غير متوفر' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user document in Firestore first
    const userRef = db.collection('users').doc();
    const uid = userRef.id;

    await userRef.set({
      uid: uid,
      username: username.toLowerCase(),
      displayName: displayName,
      hashedPassword: hashedPassword,
      photoURL: '',
      bio: '',
      followersCount: 0,
      followingCount: 0,
      isOnline: true,
      lastSeen: new Date(),
      createdAt: new Date()
    });

    // Reserve username
    await db.collection('usernames').doc(username.toLowerCase()).set({
      uid: uid
    });

    // Create custom token for authentication
    const customToken = await generateCustomToken(uid);

    return res.status(200).json({
      success: true,
      customToken: customToken,
      user: {
        uid: uid,
        username: username.toLowerCase(),
        displayName: displayName
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'حدث خطأ أثناء إنشاء الحساب' });
  }
});

// Login user
app.post('/loginUser', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'يرجى إدخال اسم المستخدم وكلمة المرور' });
    }

    // Find user by username
    const usersQuery = await db.collection('users')
      .where('username', '==', username.toLowerCase())
      .limit(1)
      .get();

    if (usersQuery.empty) {
      return res.status(400).json({ error: 'اسم المستخدم غير موجود' });
    }

    const userDoc = usersQuery.docs[0];
    const userData = userDoc.data();

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, userData.hashedPassword);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'كلمة المرور غير صحيحة' });
    }

    // Update last seen and online status
    await userDoc.ref.update({
      isOnline: true,
      lastSeen: new Date()
    });

    // Create custom token for authentication
    const customToken = await generateCustomToken(userData.uid);

    return res.status(200).json({
      success: true,
      customToken: customToken,
      user: {
        uid: userData.uid,
        username: userData.username,
        displayName: userData.displayName
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

// Check username availability
app.post('/checkUsername', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: 'اسم المستخدم مطلوب' });
    }

    const usernameDoc = await db.collection('usernames').doc(username.toLowerCase()).get();
    const isAvailable = !usernameDoc.exists;

    return res.status(200).json({
      available: isAvailable
    });

  } catch (error) {
    console.error('Username check error:', error);
    return res.status(500).json({ error: 'حدث خطأ أثناء التحقق من اسم المستخدم' });
  }
});

// Start server (for local development)
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Baynana Auth Server running on port ${PORT}`);
  });
}

module.exports = app;
