const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const sqlite3 = require('sqlite3').verbose();
const axios = require('axios');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'seu_secret_super_secreto_123';
const FOOTBALL_API_KEY = process.env.FOOTBALL_API_KEY || '';
const FOOTBALL_API_URL = 'https://api.football-data.org/v4';

// Middleware
app.use(cors());
app.use(express.json());

// ==================== BANCO DE DADOS SQLITE ====================

let db;
let dbReady = false;

function initDatabase() {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database('./bolao.db', (err) => {
      if (err) {
        console.error('❌ Erro ao conectar ao banco:', err);
        reject(err);
        return;
      }
      console.log('✅ Conectado ao SQLite');
      
      // Criar todas as tabelas em série
      db.serialize(() => {
        // Tabela de usuários
        db.run(`
          CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            points INTEGER DEFAULT 0,
            accessToken TEXT,
            isAdmin INTEGER DEFAULT 0,
            createdAt TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `, (err) => {
          if (err) console.error('Erro ao criar tabela users:', err);
          else console.log('✅ Tabela users criada/verificada');
        });

        // Tabela de partidas
        db.run(`
          CREATE TABLE IF NOT EXISTS matches (
            id TEXT PRIMARY KEY,
            footballDataId INTEGER UNIQUE,
            homeTeam TEXT NOT NULL,
            awayTeam TEXT NOT NULL,
            homeTeamLogo TEXT,
            awayTeamLogo TEXT,
            matchDate TEXT NOT NULL,
            status TEXT DEFAULT 'SCHEDULED',
            homeScore INTEGER,
            awayScore INTEGER,
            competition TEXT DEFAULT 'Premier League',
            season TEXT,
            matchday INTEGER,
            updatedAt TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `, (err) => {
          if (err) console.error('Erro ao criar tabela matches:', err);
          else console.log('✅ Tabela matches criada/verificada');
        });

        // Tabela de palpites
        db.run(`
          CREATE TABLE IF NOT EXISTS bets (
            id TEXT PRIMARY KEY,
            userId TEXT NOT NULL,
            username TEXT NOT NULL,
            matchId TEXT NOT NULL,
            homeScore INTEGER NOT NULL,
            awayScore INTEGER NOT NULL,
            points INTEGER DEFAULT 0,
            createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
            updatedAt TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(userId, matchId)
          )
        `, (err) => {
          if (err) console.error('Erro ao criar tabela bets:', err);
          else console.log('✅ Tabela bets criada/verificada');
        });

        // Tabela de tokens
        db.run(`
          CREATE TABLE IF NOT EXISTS tokens (
            id TEXT PRIMARY KEY,
            token TEXT UNIQUE NOT NULL,
            isActive INTEGER DEFAULT 1,
            usedBy TEXT,
            createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
            usedAt TEXT
          )
        `, (err) => {
          if (err) console.error('Erro ao criar tabela tokens:', err);
          else console.log('✅ Tabela tokens criada/verificada');
        });

        // Tabela de configuração
        db.run(`
          CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
          )
        `, (err) => {
          if (err) console.error('Erro ao criar tabela config:', err);
          else console.log('✅ Tabela config criada/verificada');
        });

        // Inserir dados iniciais
        const initialTokens = ['TOKEN123456', 'BOLAO2024', 'PALPITE99', 'FUTEBOL777'];
        initialTokens.forEach(token => {
          db.run(
            `INSERT OR IGNORE INTO tokens (id, token) VALUES (?, ?)`,
            [uuidv4(), token],
            (err) => {
              if (err && !err.message.includes('UNIQUE')) {
                console.error('Erro ao inserir token:', err);
              }
            }
          );
        });

        // Inserir usuário admin
        const adminPassword = bcrypt.hashSync('admin123', 10);
        db.run(
          `INSERT OR IGNORE INTO users (id, username, password, email, isAdmin, points) 
           VALUES (?, ?, ?, ?, ?, ?)`,
          ['admin-001', 'admin', adminPassword, 'admin@bolao.com', 1, 0],
          (err) => {
            if (err && !err.message.includes('UNIQUE')) {
              console.error('Erro ao criar admin:', err);
            } else {
              console.log('✅ Usuário admin verificado');
            }
          }
        );

        console.log('✅ Banco de dados inicializado com sucesso');
        dbReady = true;
        resolve();
      });
    });
  });
}

// Middleware para verificar se DB está pronto
const ensureDbReady = (req, res, next) => {
  if (!dbReady) {
    return res.status(503).json({
      success: false,
      message: 'Banco de dados ainda está inicializando. Aguarde alguns segundos.'
    });
  }
  next();
};

// ==================== MIDDLEWARE DE AUTENTICAÇÃO ====================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Token não fornecido' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        success: false, 
        message: 'Token inválido ou expirado' 
      });
    }
    req.user = user;
    next();
  });
};

// ==================== ROTAS DE AUTENTICAÇÃO ====================

app.post('/api/auth/register', ensureDbReady, async (req, res) => {
  try {
    const { username, password, access_token } = req.body;

    if (!username || !password || !access_token) {
      return res.status(400).json({
        success: false,
        message: 'Todos os campos são obrigatórios'
      });
    }

    // Verificar token de acesso
    const tokenCheck = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM tokens WHERE token = ? AND isActive = 1 AND usedBy IS NULL',
        [access_token],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!tokenCheck) {
      return res.status(403).json({
        success: false,
        message: 'Token de acesso inválido ou já utilizado'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    // Criar usuário
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO users (id, username, password, email, accessToken) 
         VALUES (?, ?, ?, ?, ?)`,
        [userId, username, hashedPassword, `${username}@bolao.com`, access_token],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Marcar token como usado
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE tokens SET usedBy = ?, usedAt = CURRENT_TIMESTAMP WHERE token = ?',
        [userId, access_token],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    const token = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      success: true,
      message: 'Usuário cadastrado com sucesso',
      data: {
        user: { id: userId, username, points: 0 },
        token
      }
    });
  } catch (error) {
    if (error.message && error.message.includes('UNIQUE')) {
      return res.status(409).json({
        success: false,
        message: 'Nome de usuário já está em uso'
      });
    }
    res.status(500).json({
      success: false,
      message: 'Erro ao cadastrar usuário',
      error: error.message
    });
  }
});

app.post('/api/auth/login', ensureDbReady, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Usuário e senha são obrigatórios'
      });
    }

    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Credenciais inválidas'
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Credenciais inválidas'
      });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Login realizado com sucesso',
      data: {
        user: {
          id: user.id,
          username: user.username,
          points: user.points
        },
        token
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Erro ao fazer login',
      error: error.message
    });
  }
});

// ==================== ROTAS DE PARTIDAS ====================

app.get('/api/matches', ensureDbReady, authenticateToken, (req, res) => {
  db.all('SELECT * FROM matches ORDER BY matchDate ASC', [], (err, rows) => {
    if (err) {
      return res.status(500).json({ success: false, message: err.message });
    }
    res.json({ success: true, data: rows || [] });
  });
});

app.get('/api/matches/:id', ensureDbReady, authenticateToken, (req, res) => {
  db.get('SELECT * FROM matches WHERE id = ?', [req.params.id], (err, row) => {
    if (err) {
      return res.status(500).json({ success: false, message: err.message });
    }
    if (!row) {
      return res.status(404).json({ success: false, message: 'Partida não encontrada' });
    }
    res.json({ success: true, data: row });
  });
});

// ==================== ROTAS DE PALPITES ====================

app.get('/api/bets/user', ensureDbReady, authenticateToken, (req, res) => {
  db.all('SELECT * FROM bets WHERE userId = ?', [req.user.id], (err, rows) => {
    if (err) {
      return res.status(500).json({ success: false, message: err.message });
    }

    const betsObject = {};
    (rows || []).forEach(bet => {
      betsObject[bet.matchId] = {
        matchId: bet.matchId,
        teamAScore: bet.homeScore,
        teamBScore: bet.awayScore,
        createdAt: bet.createdAt
      };
    });

    res.json({ success: true, data: betsObject });
  });
});

app.post('/api/bets', ensureDbReady, authenticateToken, async (req, res) => {
  try {
    const { matchId, teamAScore, teamBScore } = req.body;

    if (!matchId || teamAScore === undefined || teamBScore === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Dados incompletos'
      });
    }

    // Verificar se partida existe e não começou
    const match = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM matches WHERE id = ?', [matchId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!match) {
      return res.status(404).json({ success: false, message: 'Partida não encontrada' });
    }

    if (match.status === 'FINISHED') {
      return res.status(403).json({
        success: false,
        message: 'Não é possível palpitar em partida já finalizada'
      });
    }

    const betId = uuidv4();
    
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT OR REPLACE INTO bets 
         (id, userId, username, matchId, homeScore, awayScore, updatedAt) 
         VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
        [betId, req.user.id, req.user.username, matchId, teamAScore, teamBScore],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    res.json({
      success: true,
      message: 'Palpite salvo com sucesso',
      data: { matchId, teamAScore, teamBScore, createdAt: new Date().toISOString() }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ==================== ROTAS DE RANKING ====================

app.get('/api/ranking', ensureDbReady, authenticateToken, (req, res) => {
  db.all(
    'SELECT id, username, points FROM users ORDER BY points DESC LIMIT 100',
    [],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ success: false, message: err.message });
      }

      const ranking = (rows || []).map((user, index) => ({
        ...user,
        position: index + 1
      }));

      res.json({ success: true, data: ranking });
    }
  );
});

// ==================== ROTAS DE USUÁRIO ====================

app.get('/api/user/me', ensureDbReady, authenticateToken, (req, res) => {
  db.get('SELECT id, username, email, points FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err) {
      return res.status(500).json({ success: false, message: err.message });
    }
    if (!row) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }
    res.json({ success: true, data: row });
  });
});

// ==================== ROTAS ADMIN ====================

app.put('/api/admin/matches/:id/result', ensureDbReady, authenticateToken, async (req, res) => {
  try {
    const { teamAScore, teamBScore } = req.body;
    const matchId = req.params.id;

    if (teamAScore === undefined || teamBScore === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Placar incompleto'
      });
    }

    await new Promise((resolve, reject) => {
      db.run(
        `UPDATE matches 
         SET homeScore = ?, awayScore = ?, status = 'FINISHED', updatedAt = CURRENT_TIMESTAMP 
         WHERE id = ?`,
        [teamAScore, teamBScore, matchId],
        function(err) {
          if (err) reject(err);
          else if (this.changes === 0) reject(new Error('Partida não encontrada'));
          else resolve();
        }
      );
    });

    await calculatePointsForMatch(matchId, teamAScore, teamBScore);

    res.json({ success: true, message: 'Resultado atualizado com sucesso' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/admin/import-matches', ensureDbReady, authenticateToken, async (req, res) => {
  try {
    if (!FOOTBALL_API_KEY) {
      return res.status(400).json({
        success: false,
        message: 'FOOTBALL_API_KEY não configurada nas variáveis de ambiente'
      });
    }

    const response = await axios.get(
      `${FOOTBALL_API_URL}/competitions/PL/matches`,
      {
        headers: { 'X-Auth-Token': FOOTBALL_API_KEY },
        params: { season: '2024' }
      }
    );

    let imported = 0;
    const matches = response.data.matches || [];

    for (const match of matches) {
      const matchId = `pl_${match.id}`;
      
      await new Promise((resolve, reject) => {
        db.run(
          `INSERT OR REPLACE INTO matches 
           (id, footballDataId, homeTeam, awayTeam, homeTeamLogo, awayTeamLogo, 
            matchDate, status, homeScore, awayScore, season, matchday)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            matchId,
            match.id,
            match.homeTeam.name,
            match.awayTeam.name,
            match.homeTeam.crest || '',
            match.awayTeam.crest || '',
            match.utcDate,
            match.status,
            match.score?.fullTime?.home,
            match.score?.fullTime?.away,
            match.season?.startDate?.split('-')[0] || '2024',
            match.matchday
          ],
          (err) => {
            if (err) reject(err);
            else { 
              imported++; 
              resolve(); 
            }
          }
        );
      });
    }

    res.json({ 
      success: true, 
      message: `${imported} partidas importadas`,
      imported, 
      total: matches.length 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message,
      hint: error.response?.data?.message || 'Verifique a API Key'
    });
  }
});

// ==================== FUNÇÕES AUXILIARES ====================

async function calculatePointsForMatch(matchId, homeScore, awayScore) {
  const bets = await new Promise((resolve, reject) => {
    db.all('SELECT * FROM bets WHERE matchId = ?', [matchId], (err, rows) => {
      if (err) reject(err);
      else resolve(rows || []);
    });
  });

  for (const bet of bets) {
    const points = calculateBetPoints(bet.homeScore, bet.awayScore, homeScore, awayScore);
    
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE bets SET points = ? WHERE id = ?',
        [points, bet.id],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET points = points + ? WHERE id = ?',
        [points, bet.userId],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }
  
  console.log(`✅ Pontos calculados para ${bets.length} palpites da partida ${matchId}`);
}

function calculateBetPoints(betHome, betAway, actualHome, actualAway) {
  if (betHome === actualHome && betAway === actualAway) {
    return actualHome === actualAway ? 15 : 25;
  }

  const betResult = betHome > betAway ? 'home' : (betHome < betAway ? 'away' : 'draw');
  const actualResult = actualHome > actualAway ? 'home' : (actualHome < actualAway ? 'away' : 'draw');

  if (betResult === actualResult) return 10;
  return 0;
}

// ==================== SINCRONIZAÇÃO AUTOMÁTICA ====================

if (dbReady) {
  cron.schedule('59 23 * * *', async () => {
    console.log('🔄 Executando sincronização diária...');
    
    if (!FOOTBALL_API_KEY) {
      console.log('⚠️  FOOTBALL_API_KEY não configurada, pulando sincronização');
      return;
    }
    
    try {
      const matches = await new Promise((resolve, reject) => {
        db.all(
          `SELECT * FROM matches 
           WHERE status IN ('SCHEDULED', 'IN_PLAY') 
           AND date(matchDate) = date('now')`,
          [],
          (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          }
        );
      });

      for (const match of matches) {
        try {
          const response = await axios.get(
            `${FOOTBALL_API_URL}/matches/${match.footballDataId}`,
            { headers: { 'X-Auth-Token': FOOTBALL_API_KEY } }
          );

          if (response.data.status === 'FINISHED') {
            await new Promise((resolve, reject) => {
              db.run(
                `UPDATE matches 
                 SET status = 'FINISHED', homeScore = ?, awayScore = ? 
                 WHERE id = ?`,
                [
                  response.data.score.fullTime.home,
                  response.data.score.fullTime.away,
                  match.id
                ],
                (err) => {
                  if (err) reject(err);
                  else resolve();
                }
              );
            });

            await calculatePointsForMatch(
              match.id,
              response.data.score.fullTime.home,
              response.data.score.fullTime.away
            );

            console.log(`✅ Atualizado: ${match.homeTeam} vs ${match.awayTeam}`);
          }

          await new Promise(resolve => setTimeout(resolve, 200));
        } catch (error) {
          console.error(`❌ Erro ao processar ${match.id}:`, error.message);
        }
      }

      console.log('✅ Sincronização concluída');
    } catch (error) {
      console.error('❌ Erro na sincronização:', error);
    }
  });
}

// ==================== ROTA RAIZ ====================

app.get('/', (req, res) => {
  res.json({
    message: '⚽ API do Bolão Premier League',
    version: '2.0.1',
    status: 'online',
    database: dbReady ? 'SQLite (Ready)' : 'SQLite (Initializing...)',
    hosting: 'Render.com',
    endpoints: {
      auth: ['POST /api/auth/register', 'POST /api/auth/login'],
      matches: ['GET /api/matches', 'GET /api/matches/:id'],
      bets: ['GET /api/bets/user', 'POST /api/bets'],
      ranking: ['GET /api/ranking'],
      user: ['GET /api/user/me'],
      admin: [
        'PUT /api/admin/matches/:id/result',
        'POST /api/admin/import-matches'
      ]
    },
    tokens: ['TOKEN123456', 'BOLAO2024', 'PALPITE99', 'FUTEBOL777']
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    dbReady,
    timestamp: new Date().toISOString()
  });
});

// ==================== INICIAR SERVIDOR ====================

initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`📍 URL: https://bolao-backend-txc1.onrender.com`);
    console.log(`💾 Banco: SQLite (arquivo local)`);
    console.log(`☁️  Deploy: Render.com`);
    console.log(`✅ Sistema pronto para uso!`);
  });
}).catch((error) => {
  console.error('❌ Erro fatal ao inicializar banco:', error);
  process.exit(1);
});

process.on('SIGTERM', () => {
  if (db) {
    db.close(() => {
      console.log('Database closed.');
      process.exit(0);
    });
  }
});
