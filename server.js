// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Connexion à MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connecté à MongoDB Atlas'))
.catch(err => console.error('Erreur de connexion à MongoDB:', err));

// Schémas et Modèles Mongoose
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  firstName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const categorySchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
});

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
  price: { type: Number, required: true },
});

const User = mongoose.model('User', userSchema);
const Category = mongoose.model('Category', categorySchema);
const Product = mongoose.model('Product', productSchema);

// Middleware d'authentification
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Accès refusé. Aucun token fourni.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token invalide.' });
    }
    req.user = user;
    next();
  });
};

// --- ENDPOINTS ---

// 1. Utilisateurs

// Inscription
app.post('/api/users/register', async (req, res) => {
  try {
    const { name, firstName, email, password } = req.body;

    // Vérifie si l'utilisateur existe déjà
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Un utilisateur avec cet email existe déjà.' });
    }

    // Hache le mot de passe
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({ name, firstName, email, password: hashedPassword });
    const savedUser = await user.save();

    // Génère un token JWT (optionnel pour la connexion immédiate)
    const token = jwt.sign({ id: savedUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({ message: 'Utilisateur créé avec succès', token, user: { id: savedUser._id, name: savedUser.name, firstName: savedUser.firstName, email: savedUser.email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Connexion
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Trouve l'utilisateur par email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Email ou mot de passe incorrect.' });
    }

    // Vérifie le mot de passe
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Email ou mot de passe incorrect.' });
    }

    // Génère un token JWT
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Connexion réussie', token, user: { id: user._id, name: user.name, firstName: user.firstName, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. Catégories

// Récupérer toutes les catégories
app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const categories = await Category.find();
    res.json(categories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Créer une catégorie
app.post('/api/categories', authenticateToken, async (req, res) => {
  try {
    const { title, description } = req.body;
    const category = new Category({ title, description });
    const savedCategory = await category.save();
    res.status(201).json(savedCategory);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mettre à jour une catégorie
app.put('/api/categories/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description } = req.body;
    const updatedCategory = await Category.findByIdAndUpdate(id, { title, description }, { new: true });
    if (!updatedCategory) {
      return res.status(404).json({ error: 'Catégorie non trouvée' });
    }
    res.json(updatedCategory);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Supprimer une catégorie
app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const deletedCategory = await Category.findByIdAndDelete(id);
    if (!deletedCategory) {
      return res.status(404).json({ error: 'Catégorie non trouvée' });
    }
    res.json({ message: 'Catégorie supprimée avec succès' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. Produits

// Récupérer tous les produits
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const products = await Product.find().populate('categoryId', 'title'); // Populate la catégorie
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Créer un produit
app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { name, description, categoryId, price } = req.body;
    const product = new Product({ name, description, categoryId, price });
    const savedProduct = await product.save();
    res.status(201).json(savedProduct);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mettre à jour un produit
app.put('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, categoryId, price } = req.body;
    const updatedProduct = await Product.findByIdAndUpdate(id, { name, description, categoryId, price }, { new: true }).populate('categoryId', 'title');
    if (!updatedProduct) {
      return res.status(404).json({ error: 'Produit non trouvé' });
    }
    res.json(updatedProduct);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Supprimer un produit
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const deletedProduct = await Product.findByIdAndDelete(id);
    if (!deletedProduct) {
      return res.status(404).json({ error: 'Produit non trouvé' });
    }
    res.json({ message: 'Produit supprimé avec succès' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Route racine
app.get('/', (req, res) => {
  res.send('API Serveur - Inventory App');
});

app.listen(PORT, () => {
  console.log(`Serveur API démarré sur le port ${PORT}`);
});