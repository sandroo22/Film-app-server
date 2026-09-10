import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import mysql from 'mysql2';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

export interface CustomRequest extends Request {
    utente?: any;
}

const app = express();
const PORT = 5000;

// NUOVE CHIAVI SEGRETE PER I TOKEN (meglio se in futuro le metti in un file .env)
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || "Catania10_Access_Secret_Key!"; 
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || "Catania10_Refresh_Super_Secret_Key!"; 

app.use(cors());
app.use(express.json());

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'));
    }
});
const upload = multer({ storage: storage });

const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: 'root',     
    password: '',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Connessione con auto-creazione tabelle
db.getConnection((err, connection) => {
    if (err) {
        console.error("Errore di connessione a MySQL:", err);
        return;
    }
    console.log("Connesso al server MySQL!");

    connection.query("CREATE DATABASE IF NOT EXISTS film_db", (err) => {
        if (err) throw err;
        connection.query("USE film_db", (err) => {
            if (err) throw err;
            
            // AGGIORNATA: aggiunta colonna refresh_token
            const queryUtenti = `CREATE TABLE IF NOT EXISTS utenti (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                refresh_token VARCHAR(512) DEFAULT NULL
            )`;
            
            const queryListe = `CREATE TABLE IF NOT EXISTS liste (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome VARCHAR(255) NOT NULL,
                utente_id INT NOT NULL,
                is_default BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (utente_id) REFERENCES utenti(id) ON DELETE CASCADE
            )`;
            
            const queryFilm = `CREATE TABLE IF NOT EXISTS film (
                id INT AUTO_INCREMENT PRIMARY KEY,
                testo VARCHAR(255) NOT NULL,
                copertina VARCHAR(255),
                visto DATETIME DEFAULT NULL,
                rating INT DEFAULT 0,
                utente_id INT NOT NULL,
                lista_id INT,
                durata INT DEFAULT 0,
                genere VARCHAR(255) DEFAULT 'Non specificato',
                FOREIGN KEY (utente_id) REFERENCES utenti(id) ON DELETE CASCADE,
                FOREIGN KEY (lista_id) REFERENCES liste(id) ON DELETE SET NULL
            )`;

            const queryAttori = `CREATE TABLE IF NOT EXISTS attori (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome_cognome VARCHAR(255) NOT NULL,
                ruolo VARCHAR(255),
                film_id INT NOT NULL,
                FOREIGN KEY (film_id) REFERENCES film(id) ON DELETE CASCADE
            )`;

            const queryTags = `CREATE TABLE IF NOT EXISTS tags (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome VARCHAR(50) UNIQUE NOT NULL,
                colore VARCHAR(20) DEFAULT '#3b82f6'
            )`;

            const queryFilmTags = `CREATE TABLE IF NOT EXISTS film_tags (
                film_id INT NOT NULL,
                tag_id INT NOT NULL,
                PRIMARY KEY (film_id, tag_id),
                FOREIGN KEY (film_id) REFERENCES film(id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
            )`;

            connection.query(queryUtenti, () => {
                // Aggiornamento automatico: se la tabella utenti esisteva già, aggiungiamo la colonna refresh_token
                connection.query("ALTER TABLE utenti ADD COLUMN refresh_token VARCHAR(512) DEFAULT NULL", (err) => {
                    // Ignoriamo l'errore se la colonna esiste già (ER_DUP_FIELDNAME)
                });

                connection.query(queryListe, () => {
                    connection.query(queryFilm, () => {
                        connection.query(queryAttori, () => {
                            connection.query(queryTags, () => {
                                connection.query(queryFilmTags, () => {
                                    console.log("Tabelle verificate/create con successo!");
                                    connection.release();
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

const autenticaToken = (req: CustomRequest, res: Response, next: NextFunction): any => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 

    if (!token) return res.status(401).json({ errore: "Accesso negato, token mancante" });

    // Usa la nuova ACCESS_TOKEN_SECRET
    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, utenteDecodificato) => {
        if (err) return res.status(403).json({ errore: "Token non valido o scaduto" });
        req.utente = utenteDecodificato; 
        next();
    });
};

// ==========================
// ROTTE UTENTI & AUTH
// ==========================
app.post('/api/register', async (req: Request, res: Response): Promise<any> => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ errore: "Campi incompleti" });
    try {
        const salt = await bcrypt.genSalt(10);
        const passwordCriptata = await bcrypt.hash(password, salt);
        
        db.query("INSERT INTO utenti (email, password) VALUES (?, ?)", [email, passwordCriptata], async (err: any, result: any) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ errore: "Questa email esiste già!" });
                return res.status(500).json({ errore: err.message });
            }
            
            const nuovoUtenteId = result.insertId;
            await db.promise().query(
                "INSERT INTO liste (nome, utente_id, is_default) VALUES (?, ?, TRUE)", 
                ["Generale", nuovoUtenteId]
            );

            res.json({ messaggio: "Utente registrato con successo!" });
        });
    } catch (errore) {
        res.status(500).json({ errore: "Errore nel server" });
    }
});

app.post('/api/login', (req: Request, res: Response) => {
    const { email, password } = req.body;
    db.query("SELECT * FROM utenti WHERE email = ?", [email], async (err, results: any) => {
        if (err) return res.status(500).json({ errore: err.message });
        if (results.length === 0) return res.status(400).json({ errore: "Utente non trovato" });

        const utenteUtile = results[0];
        try {
            const passwordCorretta = await bcrypt.compare(password, utenteUtile.password);
            if (!passwordCorretta) return res.status(400).json({ errore: "Password errata" });

            const [liste]: any = await db.promise().query("SELECT id FROM liste WHERE utente_id = ? AND is_default = TRUE", [utenteUtile.id]);
            let defaultListId;
            if (liste.length === 0) {
                const [nuovaLista]: any = await db.promise().query("INSERT INTO liste (nome, utente_id, is_default) VALUES (?, ?, TRUE)", ["Generale", utenteUtile.id]);
                defaultListId = nuovaLista.insertId;
            } else {
                defaultListId = liste[0].id;
            }
            await db.promise().query("UPDATE film SET lista_id = ? WHERE utente_id = ? AND lista_id IS NULL", [defaultListId, utenteUtile.id]);

            // GENERAZIONE DEI DUE TOKEN
            const accessToken = jwt.sign({ id: utenteUtile.id, email: utenteUtile.email }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' }); // Scade in 15 minuti
            const refreshToken = jwt.sign({ id: utenteUtile.id }, REFRESH_TOKEN_SECRET, { expiresIn: '30d' }); // Scade in 30 giorni

            // Salva il refreshToken nel database
            await db.promise().query("UPDATE utenti SET refresh_token = ? WHERE id = ?", [refreshToken, utenteUtile.id]);

            // Restituisce entrambi i token al frontend
            return res.json({ 
                token: accessToken, 
                refreshToken: refreshToken 
            });
        } catch (erroreProcesso) {
            console.error("ERRORE DURANTE IL LOGIN:", erroreProcesso);
            return res.status(500).json({ errore: "Errore interno del server" });
        }
    });
});

// NUOVA ROTTA: Rinnova il token di accesso usando il refresh token
app.post('/api/refresh', async (req: Request, res: Response): Promise<any> => {
    const { refreshToken } = req.body;
    
    if (!refreshToken) return res.status(401).json({ errore: "Refresh Token mancante" });

    try {
        // Cerca l'utente che possiede questo refresh token nel database
        const [users]: any = await db.promise().query("SELECT * FROM utenti WHERE refresh_token = ?", [refreshToken]);
        if (users.length === 0) return res.status(403).json({ errore: "Refresh Token non valido o revocato" });

        const utenteUtile = users[0];

        // Verifica che il refresh token sia valido e non scaduto
        jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err: any, decoded: any) => {
            if (err) return res.status(403).json({ errore: "Refresh Token scaduto. Effettua di nuovo il login." });

            // Genera un nuovo Access Token fresco di 15 minuti
            const newAccessToken = jwt.sign({ id: utenteUtile.id, email: utenteUtile.email }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
            
            res.json({ token: newAccessToken });
        });
    } catch (error) {
        res.status(500).json({ errore: "Errore del server durante il refresh" });
    }
});

// NUOVA ROTTA: Logout (Invalida il refresh token)
app.post('/api/logout', autenticaToken, async (req: CustomRequest, res: Response): Promise<any> => {
    try {
        // Rimuove il refresh token dal database, così non potrà più essere usato per generare access token
        await db.promise().query("UPDATE utenti SET refresh_token = NULL WHERE id = ?", [req.utente.id]);
        res.json({ message: "Logout effettuato con successo" });
    } catch (error) {
        res.status(500).json({ errore: "Errore durante il logout" });
    }
});

// ==========================
// RESTO DELLE ROTTE INVARIATE
// ==========================

app.get('/api/liste', autenticaToken, (req: CustomRequest, res: Response) => {
    db.query("SELECT * FROM liste WHERE utente_id = ?", [req.utente.id], (err, results) => {
        if (err) return res.status(500).json({ errore: err.message });
        res.json(results);
    });
});

app.post('/api/liste', autenticaToken, (req: CustomRequest, res: Response): any => {
    const { nome } = req.body;
    if (!nome) return res.status(400).json({ errore: "Il nome della lista è obbligatorio" });
    db.query("INSERT INTO liste (nome, utente_id, is_default) VALUES (?, ?, FALSE)", [nome, req.utente.id], (err, result: any) => {
        if (err) return res.status(500).json({ errore: err.message });
        res.status(201).json({ message: "Lista creata", id: result.insertId });
    });
});

app.put('/api/liste/:id', autenticaToken, async (req: CustomRequest, res: Response): Promise<any> => {
    const { nome } = req.body;
    const listaId = req.params.id;
    try {
        const [lista]: any = await db.promise().query("SELECT is_default FROM liste WHERE id = ? AND utente_id = ?", [listaId, req.utente.id]);
        if (lista.length === 0) return res.status(404).json({ errore: "Lista non trovata" });
        if (lista[0].is_default) return res.status(403).json({ errore: "Non puoi rinominare la lista Generale" });

        await db.promise().query("UPDATE liste SET nome = ? WHERE id = ? AND utente_id = ?", [nome, listaId, req.utente.id]);
        res.json({ message: "Lista rinominata con successo" });
    } catch (err: any) {
        res.status(500).json({ errore: err.message });
    }
});

app.delete('/api/liste/:id', autenticaToken, async (req: CustomRequest, res: Response): Promise<any> => {
    const listaId = req.params.id;
    try {
        const [lista]: any = await db.promise().query("SELECT is_default FROM liste WHERE id = ? AND utente_id = ?", [listaId, req.utente.id]);
        if (lista.length === 0) return res.status(404).json({ errore: "Lista non trovata" });
        if (lista[0].is_default) return res.status(403).json({ errore: "Non puoi eliminare la lista Generale" });

        const [defaultList]: any = await db.promise().query("SELECT id FROM liste WHERE utente_id = ? AND is_default = TRUE", [req.utente.id]);
        
        await db.promise().query("UPDATE film SET lista_id = ? WHERE lista_id = ? AND utente_id = ?", [defaultList[0].id, listaId, req.utente.id]);
        await db.promise().query("DELETE FROM liste WHERE id = ? AND utente_id = ?", [listaId, req.utente.id]);

        res.json({ message: "Lista eliminata e film spostati in Generale" });
    } catch (err: any) {
        res.status(500).json({ errore: err.message });
    }
});

app.get('/api/film', autenticaToken, (req: CustomRequest, res: Response) => {
    db.query("SELECT * FROM film WHERE utente_id = ?", [req.utente.id], (err, results) => {
        if (err) return res.status(500).json({ errore: err.message });
        res.json(results);
    });
});

app.post('/api/film', autenticaToken, upload.single('copertina'), async (req: CustomRequest, res: Response): Promise<any> => {
    const nuovoTitolo = req.body.testo;
    let urlImmagine = null;
    let listaIdTarget = req.body.lista_id; 
    
    const durata = req.body.durata || 0;
    const genere = req.body.genere || 'Non specificato';

    if (req.file) urlImmagine = `http://localhost:5000/uploads/${req.file.filename}`;
    else if (req.body.copertina) urlImmagine = req.body.copertina;
    
    if (!nuovoTitolo) return res.status(400).json({ errore: "Il titolo non può essere vuoto" });

    try {
        if (!listaIdTarget || listaIdTarget === 'null' || listaIdTarget === 'undefined') {
            const [defaultList]: any = await db.promise().query("SELECT id FROM liste WHERE utente_id = ? AND is_default = TRUE", [req.utente.id]);
            listaIdTarget = defaultList[0].id;
        }

        await db.promise().query(
            "INSERT INTO film (testo, copertina, utente_id, lista_id, durata, genere) VALUES (?, ?, ?, ?, ?, ?)", 
            [nuovoTitolo, urlImmagine, req.utente.id, listaIdTarget, durata, genere]
        );

        const [results] = await db.promise().query("SELECT * FROM film WHERE utente_id = ?", [req.utente.id]);
        res.json(results);
    } catch (err: any) {
        res.status(500).json({ errore: err.message });
    }
});

app.put('/api/film/:id', autenticaToken, (req: CustomRequest, res: Response) => {
    const idDaModificare = req.params.id;
    const { testo, lista_id } = req.body; 

    let query = "UPDATE film SET testo = ?";
    let queryParams = [testo];

    if (lista_id) {
        query += ", lista_id = ?";
        queryParams.push(lista_id);
    }

    query += " WHERE id = ? AND utente_id = ?";
    queryParams.push(idDaModificare, req.utente.id);

    db.query(query, queryParams, (err, result) => {
        if (err) return res.status(500).json({ errore: err.message });
        db.query("SELECT * FROM film WHERE utente_id = ?", [req.utente.id], (err, results) => {
            if (err) return res.status(500).json({ errore: err.message });
            res.json(results);
        });
    });
});

app.patch('/api/film/:id/visto', autenticaToken, (req: CustomRequest, res: Response) => {
    const idDaModificare = req.params.id;
    const setVisto = req.body.visto; 
    
    const query = setVisto 
        ? "UPDATE film SET visto = NOW() WHERE id = ? AND utente_id = ?" 
        : "UPDATE film SET visto = NULL WHERE id = ? AND utente_id = ?";

    db.query(query, [idDaModificare, req.utente.id], (err, result) => {
        if (err) return res.status(500).json({ errore: err.message });
        db.query("SELECT * FROM film WHERE utente_id = ?", [req.utente.id], (err, results) => {
            if (err) return res.status(500).json({ errore: err.message });
            res.json(results);
        });
    });
});

app.patch('/api/film/:id/rating', autenticaToken, (req: CustomRequest, res: Response) => {
    const idDaModificare = req.params.id;
    const nuovoVoto = req.body.rating; 
    db.query("UPDATE film SET rating = ? WHERE id = ? AND utente_id = ?", [nuovoVoto, idDaModificare, req.utente.id], (err, result) => {
        if (err) return res.status(500).json({ errore: err.message });
        db.query("SELECT * FROM film WHERE utente_id = ?", [req.utente.id], (err, results) => {
            if (err) return res.status(500).json({ errore: err.message });
            res.json(results);
        });
    });
});

app.delete('/api/film/:id', autenticaToken, (req: CustomRequest, res: Response) => {
    const idDaEliminare = req.params.id;
    db.query("DELETE FROM film WHERE id = ? AND utente_id = ?", [idDaEliminare, req.utente.id], (err, result) => {
        if (err) return res.status(500).json({ errore: err.message });
        db.query("SELECT * FROM film WHERE utente_id = ?", [req.utente.id], (err, results) => {
            if (err) return res.status(500).json({ errore: err.message });
            res.json(results);
        });
    });
});

app.get('/api/film/:filmId/attori', autenticaToken, (req: CustomRequest, res: Response): any => {
    const filmId = req.params.filmId;
    db.query("SELECT * FROM film WHERE id = ? AND utente_id = ?", [filmId, req.utente.id], (err, results: any) => {
        if (err) return res.status(500).json({ errore: err.message });
        if (results.length === 0) return res.status(403).json({ errore: "Accesso negato" });
        db.query("SELECT * FROM attori WHERE film_id = ?", [filmId], (err, attori) => {
            if (err) return res.status(500).json({ errore: err.message });
            res.json(attori);
        });
    });
});

app.post('/api/film/:filmId/attori', autenticaToken, (req: CustomRequest, res: Response): any => {
    const filmId = req.params.filmId;
    const { nome_cognome, ruolo } = req.body; 
    db.query("SELECT * FROM film WHERE id = ? AND utente_id = ?", [filmId, req.utente.id], (err, results: any) => {
        if (err) return res.status(500).json({ errore: err.message });
        if (results.length === 0) return res.status(403).json({ errore: "Accesso negato" });
        db.query("INSERT INTO attori (nome_cognome, ruolo, film_id) VALUES (?, ?, ?)", [nome_cognome, ruolo || null, filmId], (err, result) => {
            if (err) return res.status(500).json({ errore: err.message });
            res.status(201).json({ message: "Attore salvato con successo" });
        });
    });
});

app.get('/api/film/:id/tags', autenticaToken, async (req: CustomRequest, res: Response): Promise<any> => {
    const filmId = req.params.id;
    try {
        const [checkFilm]: any = await db.promise().query("SELECT id FROM film WHERE id = ? AND utente_id = ?", [filmId, req.utente.id]);
        if (checkFilm.length === 0) return res.status(403).json({ error: "Accesso negato al film" });

        const [tags] = await db.promise().query(
            `SELECT t.id, t.nome, t.colore 
             FROM tags t
             JOIN film_tags ON t.id = film_tags.tag_id
             WHERE film_tags.film_id = ?`, 
            [filmId]
        );
        res.json(tags);
    } catch (err) {
        console.error("Errore recupero tag:", err);
        res.status(500).json({ error: "Errore interno del server" });
    }
});

app.post('/api/film/:id/tags', autenticaToken, async (req: CustomRequest, res: Response): Promise<any> => {
    const filmId = req.params.id;
    const { nome_tag, colore } = req.body; 

    if (!nome_tag) {
        return res.status(400).json({ error: "Il nome del tag è obbligatorio" });
    }

    try {
        const [checkFilm]: any = await db.promise().query("SELECT id FROM film WHERE id = ? AND utente_id = ?", [filmId, req.utente.id]);
        if (checkFilm.length === 0) return res.status(403).json({ error: "Accesso negato al film" });

        const [tagEsistente]: any = await db.promise().query("SELECT id FROM tags WHERE nome = ?", [nome_tag]);

        let tagId;

        if (tagEsistente.length > 0) {
            tagId = tagEsistente[0].id;
        } else {
            const coloreTag = colore || '#3b82f6'; 
            const [nuovoTag]: any = await db.promise().query(
                "INSERT INTO tags (nome, colore) VALUES (?, ?)", 
                [nome_tag, coloreTag]
            );
            tagId = nuovoTag.insertId;
        }

        await db.promise().query("INSERT IGNORE INTO film_tags (film_id, tag_id) VALUES (?, ?)", [filmId, tagId]);

        res.status(201).json({ message: "Tag salvato e associato con successo!", tag_id: tagId });
    } catch (err) {
        console.error("Errore salvataggio tag:", err);
        res.status(500).json({ error: "Errore interno del server" });
    }
});

app.delete('/api/film/:filmId/tags/:tagId', autenticaToken, async (req: CustomRequest, res: Response): Promise<any> => {
    const filmId = req.params.filmId;
    const tagId = req.params.tagId;

    try {
        const [checkFilm]: any = await db.promise().query("SELECT id FROM film WHERE id = ? AND utente_id = ?", [filmId, req.utente.id]);
        if (checkFilm.length === 0) return res.status(403).json({ error: "Accesso negato al film" });

        await db.promise().query("DELETE FROM film_tags WHERE film_id = ? AND tag_id = ?", [filmId, tagId]);
        res.json({ message: "Tag rimosso dal film con successo!" });
    } catch (err) {
        console.error("Errore rimozione tag:", err);
        res.status(500).json({ error: "Errore interno del server" });
    }
});

app.get('/api/statistiche', autenticaToken, async (req: CustomRequest, res: Response) => {
    const utenteId = req.utente.id;

    try {
        const [statsBase]: any = await db.promise().query(`
            SELECT 
                COUNT(*) AS totale_film,
                SUM(CASE WHEN visto IS NOT NULL THEN 1 ELSE 0 END) AS film_visti,
                SUM(CASE WHEN visto IS NULL THEN 1 ELSE 0 END) AS film_da_vedere,
                SUM(CASE WHEN visto IS NOT NULL THEN durata ELSE 0 END) AS minuti_totali_visti
            FROM film
            WHERE utente_id = ?
        `, [utenteId]);

        const [statsGeneri]: any = await db.promise().query(`
            SELECT 
                genere, 
                SUM(durata) AS minuti_visti 
            FROM film
            WHERE visto IS NOT NULL AND utente_id = ?
            GROUP BY genere
            ORDER BY minuti_visti DESC
        `, [utenteId]);

        const [statsListe]: any = await db.promise().query(`
            SELECT COUNT(*) AS totale_liste FROM liste WHERE utente_id = ?
        `, [utenteId]);

        const [ultimiVisti]: any = await db.promise().query(`
            SELECT id, testo, copertina, visto, durata, genere, rating
            FROM film 
            WHERE utente_id = ? AND visto IS NOT NULL 
            ORDER BY visto DESC 
            LIMIT 3
        `, [utenteId]);

        res.json({
            totali: {
                ...statsBase[0],
                totale_liste: statsListe[0].totale_liste
            },
            perGenere: statsGeneri,
            ultimiVisti: ultimiVisti
        });
    } catch (err: any) {
        console.error("Errore nel calcolo delle statistiche:", err);
        res.status(500).json({ errore: "Errore interno del server" });
    }
});

app.get('/api/export', autenticaToken, async (req: CustomRequest, res: Response) => {
    try {
        const [liste] = await db.promise().query("SELECT nome, is_default FROM liste WHERE utente_id = ?", [req.utente.id]);
        const [film] = await db.promise().query(`
            SELECT f.testo, f.copertina, f.visto, f.rating, f.durata, f.genere, l.nome as lista_nome
            FROM film f
            LEFT JOIN liste l ON f.lista_id = l.id
            WHERE f.utente_id = ?
        `, [req.utente.id]);
        res.json({ liste, film });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Errore durante l'esportazione." });
    }
});

app.post('/api/import', autenticaToken, async (req: CustomRequest, res: Response): Promise<any> => {
    const { liste, film } = req.body;
    if (!liste || !film) return res.status(400).json({ error: "Formato JSON non valido." });

    try {
        await db.promise().beginTransaction();

        await db.promise().query("DELETE FROM film WHERE utente_id = ?", [req.utente.id]);
        await db.promise().query("DELETE FROM liste WHERE utente_id = ? AND is_default = FALSE", [req.utente.id]);

        for (const l of liste) {
            if (!l.is_default) {
                await db.promise().query("INSERT IGNORE INTO liste (nome, utente_id, is_default) VALUES (?, ?, FALSE)", [l.nome, req.utente.id]);
            }
        }

        const [listeAttuali]: any = await db.promise().query("SELECT id, nome, is_default FROM liste WHERE utente_id = ?", [req.utente.id]);
        const mappaListe: any = {};
        let defaultListId = null;
        listeAttuali.forEach((l: any) => {
            mappaListe[l.nome] = l.id;
            if (l.is_default) defaultListId = l.id;
        });

        for (const f of film) {
            const lista_id = mappaListe[f.lista_nome] || defaultListId;
            
            let dataVisto = null;
            if (f.visto === true || f.visto === 1) dataVisto = new Date();
            else if (typeof f.visto === 'string' && f.visto) dataVisto = f.visto; 

            await db.promise().query(
                "INSERT INTO film (testo, copertina, visto, rating, durata, genere, utente_id, lista_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [f.testo, f.copertina || null, dataVisto, f.rating || 0, f.durata || 0, f.genere || 'Non specificato', req.utente.id, lista_id]
            );
        }

        await db.promise().commit();
        res.json({ message: "Importazione completata!" });
    } catch (err) {
        await db.promise().rollback();
        console.error(err);
        res.status(500).json({ error: "Errore durante l'importazione." });
    }
});

app.listen(PORT, () => {
    console.log(`Server attivo sulla porta ${PORT}`);
});