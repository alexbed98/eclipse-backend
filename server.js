import express from 'express';
import cors from 'cors';
import { getConnection } from './db.js';

import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// cle secrete pour signer les token (a changer)
// a mettre dans un .env quand le site va etre deploye
const JWT_SECRET = 'QwErTy123$';

// pour le hashage de mot de pass
const SALT_ROUNDS = 10;

const app = express();

// middlewares
app.use(cors({
  origin: 'http://localhost:5173', // Remplace par l'URL/port de ton React
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// middleware qui verifie le token de connexion
function checkToken(req, res, next) {
  // recuperation de l'entente autorisation envoyer par le client
  const authHeader = req.headers['authorization'];

  // la syntaxe ressemble a "Bearer TOKEN" don
  //  on recupere le jeton apres l'espace avec split
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: "Acces refuse. token manquant" });
  }

  // verification du token avec la cle secrete
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) {
      return res.status(403).json({ message: "Token invalide ou expire" });
    }

    // payload contient { id, email } (defini lors du jwt.sign())
    req.user = payload;

    // pour passer au middleware ou la route suivante
    next();
  })
}

// recupere le profil du joueur connecte
app.get('/api/me', checkToken, async (req, res) => {
  let conn;
  try {
    const userId = req.user.id;

    conn = await getConnection();

    const rows = await conn.query(
      'SELECT id, alias, prenom, nom, adresse_courriel, nbPiece, est_admin FROM Joueurs WHERE id = ?',
      [userId]
    );

    if (!rows[0]) {
      return res.status(404).json({ message: "Joueur introuvable" });
    }

    res.json(rows[0]);
  }
  catch (err) {
    console.error("erreur /api/me", err);
    res.status(500).json({ error: "Erreur de serveur" });
  }
  finally {
    if (conn) conn.release();
  }
});

// etabli le joueur connecte en session
app.post('/api/login', async (req, res) => {
  let conn;
  try {
    const { adresse_courriel, mot_de_passe } = req.body;

    // verifier si les champs sont remplis
    if (!adresse_courriel || !mot_de_passe) {
      return res.status(400).json({ message: "Courriel et mot de passe requis" });
    }

    conn = await getConnection();

    // chercher le joueur avec son courriel
    const rows = await conn.query(
      'SELECT id, alias, nom, prenom, adresse_courriel, hash_mdp FROM Joueurs WHERE adresse_courriel = ?',
      [adresse_courriel]
    );

    if (!rows[0]) {
      return res.status(401).json({ message: "Identifiants invalides" });
    }

    const joueur = rows[0];

    // verifier le mot de passe hasher avec bcrypt
    const mdpValide = await bcrypt.compare(mot_de_passe, joueur.hash_mdp);
    if (!mdpValide) {
      return res.status(401).json({ message: "Identifiants invalides" });
    }

    // generer le token en utilisant le courriel et l'id du joueur
    // et la phrase secrete
    const token = jwt.sign(
      { id: joueur.id, email: joueur.adresse_courriel },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    // retourner le token et les infos du joueurs
    res.json({
      token: token,
      joueur: {
        id: joueur.id,
        alias: joueur.alias,
        prenom: joueur.prenom,
        nom: joueur.nom,
        adresse_courriel: joueur.adresse_courriel
      }
    });
  }
  catch (err) {
    console.error("Erreur login:", err);
    res.status(500).json({ error: "Erreur lors de la connexion" });
  }
  finally {
    if (conn) conn.release();
  }
});

// creation du compte d'un joueur
app.post('/api/register', async (req, res) => {
  let conn;
  try {
    const { alias, nom, prenom, adresse_courriel, mot_de_passe } = req.body;
    const hashedPassword = await bcrypt.hash(mot_de_passe, SALT_ROUNDS);

    conn = await getConnection();

    await conn.query(
      'INSERT INTO joueurs (alias, nom, prenom, adresse_courriel, hash_mdp) VALUES (?, ?, ?, ?, ?)',
      [alias, nom, prenom, adresse_courriel, hashedPassword]
    );

    res.status(201).json({ message: "Joueur cree avec succes" });
  }
  catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur lors de la creation de compte" })
  }
  finally {
    if (conn) conn.release();
  }
})

// modification du profil d'un joueur
app.put('/api/profile', checkToken, async (req, res) => {
  let conn;
  try {
    const { alias, nom, prenom, adresse_courriel, mot_de_passe } = req.body;
    const userId = req.user.id;

    conn = await getConnection();

    if (mot_de_passe) {
      const hashedPassword = await bcrypt.hash(mot_de_passe, SALT_ROUNDS);

      await conn.query(
        'UPDATE joueurs SET alias = ?, nom = ?, prenom = ?, adresse_courriel = ?, hash_mdp = ? WHERE id = ?',
        [alias, nom, prenom, adresse_courriel, hashedPassword, userId]
      );
    }
    else {
      await conn.query(
        'UPDATE joueurs SET alias = ?, nom = ?, prenom = ?, adresse_courriel = ? WHERE id = ?',
        [alias, nom, prenom, adresse_courriel, userId]
      );
    }

    const rows = await conn.query(
      'SELECT id, alias, nom, prenom, adresse_courriel FROM joueurs WHERE id = ?',
      [userId]
    );

    const updatedUser = rows[0];

    res.status(200).json({ 
      message: "Profil modifie avec succes",
      player: updatedUser
     });
  }
  catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur lors de la modification de profil" })
  }
  finally {
    if (conn) conn.release();
  }
})

// select un joueur selon le id passe en parametre
app.get('/api/joueurs/:id', async (req, res) => {
  let conn;
  try {
    const joueurId = req.params.id;
    conn = await getConnection();

    const rows = await conn.query(
      'SELECT id, alias, nom, prenom, adresse_courriel FROM Joueurs WHERE id = ?',
      [joueurId]
    );

    res.json(rows[0]);
  }
  catch (err) {
    console.error("Erreur SQL:", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
  finally {
    if (conn) conn.release();
  }
});

// Faire apparaître les cartes dans la section collection
app.get('/api/collection/:id', async (req, res) => {
  let conn;

  try{
    const joueurId = req.params.id;
    conn = await getConnection();
    const rows = await conn.query(
      'SELECT cartes.*, COALESCE(collections.quantite, 0) AS quantite from cartes LEFT JOIN collections ON cartes.id = collections.id_carte AND  collections.id_joueur = ?',
      [joueurId]
    )
      res.json(rows);
  } catch (error){
      console.error("Erreur SQL:", error);
      res.status(500).json({ error: "Erreur serveur" });
  }
  finally {
    if (conn) conn.release();
  }
})


app.get('/api/shop', async (req, res) => {
  let conn;

  try{
    conn = await getConnection();
    const rows = await conn.query(
      'SELECT * FROM paquets'
    )
    res.json(rows);
  } catch (error){
      console.error("Erreur SQL:", error);
      res.status(500).json({ error: "Erreur serveur!" });
  }
  finally {
    if (conn) conn.release();
  }

})

// Obtention des détails d'une carte
app.get('/api/inventory/details/:id', async (req, res) => {
  let conn;

  try{
    const carteId = req.params.id;
    conn = await getConnection();
    const rows = await conn.query(
      `SELECT cartes.*, COALESCE(collections.quantite, 0) AS quantite  FROM cartes 
      LEFT JOIN collections ON cartes.id = collections.id_carte  WHERE id = ?`, [carteId]
    )
    res.json(rows[0]);
  }
  catch (err) {
    console.error("Erreur SQL:", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
  finally {
    if (conn) conn.release();
  }
});

// Lancement du serveur express sur le port 5000
app.listen(5000, () => {
  console.log("Serveur backend démarré sur http://localhost:5000");
});
