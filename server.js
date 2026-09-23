import express from 'express';
import cors from 'cors';
import { getConnection } from './db.js';

import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// cle secrete pour signer les token (a changer)
// a mettre dans un .env quand le site va etre deploye
const JWT_SECRET = 'QwErTy123$';

const app = express();

// middlewares
app.use(cors());
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
      return res.status(403).json({ message: "Token invalide ou expire"});
    }

    // payload contient { id, email } (defini lors du jwt.sign())
    req.joueur = payload;

    // pour passer au middleware ou la route suivante
    next();
  })
}

// recupere le profil du joueur connecte
app.get('/api/me', checkToken, async (req, res) => {
  let conn;
  try {
    const joueurId = req.joueur.id;

    conn = await getConnection();

    const rows = await conn.query(
      'SELECT id, alias, prenom, nom, adresse_courriel, nbPiece, est_admin FROM Joueurs WHERE id = ?',
      [joueurId]
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

    // verifier le mot de passe (pour l'instant ils ne sont pas hashes)
    // on va utiliser bcrypt plus tard
    const mdpValide = mot_de_passe === joueur.hash_mdp;
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

// Lancement du serveur express sur le port 5000
app.listen(5000, () => {
  console.log("Serveur backend démarré sur http://localhost:5000");
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