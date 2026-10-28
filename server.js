import express from 'express';
import cors from 'cors';
import { getConnection } from './db.js';
import 'dotenv/config';

import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';


const JWT_SECRET = process.env.JWT_SECRET;

// pour le hashage de mot de pass
const SALT_ROUNDS = 10;

const app = express();

// middlewares
app.use(cors({
  origin: ['http://localhost:5173', 'http://158.69.48.57'], 
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
app.get('/api/inventory/details/:id/:joueurId', async (req, res) => {
  let conn;

  try{
    const carteId = req.params.id;
    const joueurId = req.params.joueurId;
    conn = await getConnection();
    const rows = await conn.query(
      `SELECT cartes.*, COALESCE(collections.quantite, 0) AS quantite  FROM cartes 
      LEFT JOIN collections ON cartes.id = collections.id_carte AND collections.id_joueur = ?  WHERE id = ?`, [joueurId, carteId]
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


// Récupération du nombre de pièce d'un joueur
app.get('/api/shop/:id', async (req, res) => {
  let conn;
  try {
    const joueurId = req.params.id;
    conn = await getConnection();

    const rows = await conn.query(
      'SELECT nbPiece FROM Joueurs WHERE id = ?',
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

app.get('/api/shop/:id/:currency/:idBooster', async (req, res) => {
  let conn;
  try{
    const joueurId = req.params.id;
    const currency = req.params.currency
    const idBooster = req.params.idBooster

    conn = await getConnection();

    // Partie concernant la gestion de currency du joueur
    const rows = await conn.query(
      'SELECT nbPiece FROM Joueurs Where id = ?',
      [joueurId]
    );

    const joueurCurrency = rows[0].nbPiece

    if(joueurCurrency >= currency){
      const rowUpdated = await conn.query(
        'UPDATE Joueurs SET nbPiece = nbPiece - ? WHERE id = ?',
        [currency, joueurId]
      );

      // Partie concernant les cartes à ajouter au joueur suite à son achat
      const boosterCards = await conn.query(
        'SELECT * FROM paquets_cartes WHERE id_paquet = ?',
        [idBooster]
      );

      const cardsObtained = [];
        
      for(let i = 0; i < 10; i++){

        const number = Math.random();
          
        let probability = 0
          
        for(const card of boosterCards){
          probability += Number(card.probabilite);

          if(number < probability){
            cardsObtained.push(card.id_carte);
            break;
          }
        }
      }

      for(let i = 0; i < cardsObtained.length; i++){
        await conn.query(
          `CALL ajouter_carte(${joueurId}, ${cardsObtained[i]})`
        )
      }
        
      res.json({
        success: true,
        message: "Achat effectué",
        updatedCurrency: joueurCurrency - currency,
        cardsObtained: cardsObtained
      });
    }
    else{
      res.json({
        success: false,
        message: "Pas assez de pièces"
      });
    }
  }
  catch (err) {
    console.error("Erreur SQL:", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
  finally {
    if (conn) conn.release();
  }
});

// Récupération des decks du joueur
app.get('/api/decks/:id', async (req,res) => {
  let conn;
  const joueurId = req.params.id;

  try{
    conn = await getConnection();
    const rows = await conn.query(
      'SELECT * FROM decks WHERE id_joueur = ?', [joueurId]
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

// Récupération des cartes dans un deck d'un joueur
app.get('/api/deck/cartes/:idDeck', async (req, res) => {
  let conn;
  const idDeck = req.params.idDeck;

  try{
    conn = await getConnection();
    const rows = await conn.query(
      'SELECT decks_cartes.*, decks.nom FROM decks_cartes INNER JOIN decks ON decks_cartes.id_deck = decks.id WHERE id_deck = ?', [idDeck])
      res.json(rows);
  } catch(error){
      console.error("Erreur SQL:", error);
      res.status(500).json({ error: "Erreur serveur!" });
  }
  finally {
    if (conn) conn.release();
  }
})

// Ajout d'une carte dans un deck
app.get('/api/deck/cartes/:idCarte/:idDeck', async (req, res) => {
  let conn;
  const idDeck = req.params.idDeck;
  const idCarte = req.params.idCarte;
  try{
    conn = await getConnection();

    await conn.query(
      `CALL ajouter_carte_deck(${idDeck}, ${idCarte})`
    )

    return res.status(200).json({ message: "Carte ajoutée au deck avec succès" });

  } catch(error){
      console.error("Erreur SQL:", error);
      if (error.code === 'ER_SIGNAL_EXCEPTION') {

        let codeError;

        switch (error.sqlMessage){
          case 'Impossible : maximum de 2 copies de cette carte.':
            codeError = "MAX_COPIES"
            break;

          case 'Impossible : le deck contient déjà 20 cartes.':
            codeError = "DECK_FULL"
            break;

          case 'Impossible : vous ne possédez pas assez de copies de cette carte.':
            codeError = "INSUFFICIENT_COPIES"
            break;

          default:
            codeError = "ERROR";
        }

        return res.status(400).json({
            code: codeError,
            message: error.sqlMessage
        });
      }
      return res.status(500).json({
        code: "SERVER_ERROR",
        message: "Erreur serveur!"
      });
  }
  finally {
    if (conn) conn.release();
  }
})

// Retirer une carte d'un deck
app.get('/api/deck/cartes/retirer/:idCarte/:idDeck', async (req, res) => {
  let conn;
  const idDeck = req.params.idDeck;
  const idCarte = req.params.idCarte;
  try{
    conn = await getConnection();

    await conn.query(
      `CALL retirer_carte_deck(${idDeck}, ${idCarte})`
    )

    return res.status(200).json({ message: "Carte retirée du deck avec succès" });

  } catch(error){
      console.error("Erreur SQL:", error);
      res.status(500).json({ error: "Erreur serveur!" });
  }
  finally {
    if (conn) conn.release();
  }
})

// Créer un deck
app.get('/api/decks/:id/:deckTitle', async (req, res) => {
  let conn;
  const idJoueur = req.params.id;
  const deckTitle = req.params.deckTitle;
  try{
    conn = await getConnection();

    await conn.query(
      `INSERT INTO decks (id_joueur, nom) VALUES (?, ?)`, [idJoueur, deckTitle]
    )

    return res.status(200).json({ message: "Deck créé avec succès" });

  } catch(error){
      console.error("Erreur SQL:", error);
      res.status(500).json({ error: "Erreur serveur!" });
  }
  finally {
    if (conn) conn.release();
  }
})

// Effacer un deck
app.get('/api/deckDetails/delete/:id', async (req, res) => {
  let conn;
  const idDeck = req.params.id;

  try{
    conn = await getConnection();
    await conn.beginTransaction();

    await conn.query(
      'DELETE FROM decks_cartes WHERE id_deck = ?', [idDeck]
    );

    await conn.query(
      'DELETE FROM decks WHERE id = ?', [idDeck]
    );

    await conn.commit();

    return res.status(200).json({ message: "Deck effacé avec succès" });

  } catch(error){
      if (conn) {
        await conn.rollback();
      }
      console.error("Erreur SQL:", error);
      res.status(500).json({ error: "Erreur serveur!" });
  }
  finally {
    if (conn) conn.release();
  }
})

// Récupérer le nom du deck
app.get('/api/deckDetails/name/:id', async (req, res) => {
  let conn;

  const idDeck = req.params.id;

  try{
    conn = await getConnection();

    const rows = await conn.query(
      `SELECT nom FROM decks WHERE id = ?`, [idDeck]
    )

    res.json(rows[0]);

  } catch(error){
      console.error("Erreur SQL:", error);
      res.status(500).json({ error: "Erreur serveur!" });
  }
  finally {
    if (conn) conn.release();
  }
})

app.get('/api/deckDetails/:id', async (req, res) => {
  let conn;

  try{
    const joueurId = req.params.id;
    conn = await getConnection();
    const rows = await conn.query(
      'SELECT cartes.*, COALESCE(collections.quantite, 0) AS quantite from cartes INNER JOIN collections ON cartes.id = collections.id_carte AND  collections.id_joueur = ?',
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

// Faire apparaître les cartes en ventes sur le marché
app.get('/api/market', async (req, res) => {
  let conn;

  try{
    conn = await getConnection();
    const rows = await conn.query(
      `SELECT 
        m.id AS id_sale,
        m.prix AS sale_price,
        m.quantite AS sale_qty,
        c.id AS id_card,
        c.nom AS card_name,
        c.id_rarete AS id_rarity,
        c.id_serie AS id_serie,
        j.id AS id_seller,
        j.alias AS seller_username 
      FROM Marche m
      JOIN Cartes c ON m.id_carte = c.id
      JOIN Joueurs j ON m.id_joueur = j.id;`
    )
      res.json(rows);
  } catch (error){
      console.error("Erreur SQL:", error);
      res.status(500).json({ error: "Erreur serveur" });
  }
  finally {
    if (conn) conn.release();
  }
});

// Pour mettre une carte en vente sur le marché
app.post('/api/market/sell', async (req, res) => {
  const { joueur, carte, quantiteAjoutee, nouveauPrix } = req.body;
  let conn;

  try {
    conn = await getConnection();
    await conn.query('CALL vendre_carte(?, ?, ? ,?)', [ joueur, carte, quantiteAjoutee, nouveauPrix]);
    res.status(200).json({ message: "Vente réussie" });
  }
  catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erreur serveur lors de la vente" });
  }
  finally {
    if (conn) conn.release();
  }

});

// Pour retirer une carte en vente sur le marché
app.delete('/api/market/:id', async (req, res) => {
  const saleId = req.params.id;
  let conn;

  try {
    conn = await getConnection();

    await conn.query('CALL retirer_carte(?)', [saleId]);

    res.status(200).json({ message: "Vente retirée du marché avec succès"});
  }
  catch (err) {
    console.error("Erreur SQL:", err);
    res.status(500).json({ message: "Erreur du serveur lors du retrait du marché" });
  }
  finally {
    if (conn) conn.release();
  }
})

// Pour acheter une carte dans le marché
app.post('/api/market/buy', checkToken, async (req, res) => {
  const { saleId, quantity } = req.body;
  const buyerId = req.user.id;
  let conn;

  try {
    conn = await getConnection();
    await conn.query('CALL acheter_carte(?, ?, ?)', [buyerId, saleId, quantity]);
    res.status(200).json({ message: 'Achat effectué avec succès!' });
  }
  catch (err) {
    console.error("Erreur lors de l'achat sur le marché", err);
    res.status(500).json({ message: err.message || "Erreur du serveur lors de l'achat sur le marché" });
  }
  finally {
    if (conn) conn.release();
  }
});

// Lancement du serveur express sur le port 5000
app.listen(5000, () => {
  console.log("Serveur backend démarré sur http://localhost:5000");
});
