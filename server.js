// server.js - VERSÃO COMPLETA COM ADMIN
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Variáveis de ambiente
const JWT_SECRET = process.env.JWT_SECRET || 'seu-secret-super-secreto-aqui-12345';
const FOOTBALL_API_KEY = process.env.FOOTBALL_API_KEY || 'sua-chave-aqui';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'ADMIN_MASTER_2025'; // 🔑 TOKEN ADMIN PADRÃO

// Middlewares
app.use(cors());
app.use(express.json());

// ==================== BANCO DE DADOS ====================

const db = new sqlite3.Database('./bolao.db', (err) => {
  if (err) {
    console.error('❌ Erro ao conectar no banco:', err);
  } else {
    console.log('✅ Conectado ao SQLite');
  }
});

// Criar tabelas
db.serialize(() => {
  // Tabela de usuários COM ROLE
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      points INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Tabela de partidas
  db.run(`
    CREATE TABLE IF NOT EXISTS matches (
      id TEXT PRIMARY KEY,
      teamA TEXT NOT NULL,
      teamB TEXT NOT NULL,
      date TEXT NOT NULL,
      status TEXT DEFAULT 'upcoming',
      teamAScore INTEGER,
      teamBScore INTEGER,
      competition TEXT DEFAULT 'Champions League',
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Tabela de palpites
  db.run(`
    CREATE TABLE IF NOT EXISTS bets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      match_id TEXT NOT NULL,
      teamAScore INTEGER NOT NULL,
      teamBScore INTEGER NOT NULL,
      points INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (match_id) REFERENCES matches(id),
      UNIQUE(user_id, match_id)
    )
  `);

  // Tabela de tokens de acesso
  db.run(`
    CREATE TABLE IF NOT EXISTS access_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      is_admin BOOLEAN DEFAULT 0,
      used BOOLEAN DEFAULT 0,
      used_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (used_by) REFERENCES users(id)
    )
  `);

  console.log('✅ Tabelas criadas/verificadas');

  // Inserir token admin padrão se não existir
  db.get('SELECT * FROM access_tokens WHERE token = ?', [ADMIN_TOKEN], (err, row) => {
    if (!row) {
      db.run(
        'INSERT INTO access_tokens (token, is_admin) VALUES (?, 1)',
        [ADMIN_TOKEN],
        () => {
          console.log(`🔑 Token Admin criado: ${ADMIN_TOKEN}`);
        }
      );
    }
  });
});

// ==================== MIDDLEWARE DE AUTENTICAÇÃO ====================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Token não fornecido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Middleware para verificar se é admin
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      success: false, 
      message: 'Acesso negado. Apenas administradores.' 
    });
  }
  next();
};

// ==================== ROTAS DE AUTENTICAÇÃO ====================

// Registro
app.post('/api/auth/register', async (req, res) => {
  const { username, password, access_token } = req.body;

  if (!username || !password || !access_token) {
    return res.status(400).json({ 
      success: false, 
      message: 'Username, senha e token são obrigatórios' 
    });
  }

  try {
    // Verificar se o token de acesso é válido
    db.get(
      'SELECT * FROM access_tokens WHERE token = ? AND used = 0',
      [access_token],
      async (err, tokenRow) => {
        if (err || !tokenRow) {
          return res.status(400).json({ 
            success: false, 
            message: 'Token de acesso inválido ou já utilizado' 
          });
        }

        // Hash da senha
        const hashedPassword = await bcrypt.hash(password, 10);

        // Determinar role baseado no token
        const userRole = tokenRow.is_admin ? 'admin' : 'user';

        // Criar usuário
        db.run(
          'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
          [username, hashedPassword, userRole],
          function(err) {
            if (err) {
              if (err.message.includes('UNIQUE')) {
                return res.status(400).json({ 
                  success: false, 
                  message: 'Username já existe' 
                });
              }
              return res.status(500).json({ 
                success: false, 
                message: 'Erro ao criar usuário' 
              });
            }

            const userId = this.lastID;

            // Marcar token como usado
            db.run(
              'UPDATE access_tokens SET used = 1, used_by = ? WHERE token = ?',
              [userId, access_token]
            );

            // Gerar JWT
            const jwtToken = jwt.sign(
              { id: userId, username, role: userRole },
              JWT_SECRET,
              { expiresIn: '30d' }
            );

            res.json({
              success: true,
              message: `Usuário ${userRole === 'admin' ? 'ADMIN' : ''} criado com sucesso`,
              data: {
                token: jwtToken,
                user: {
                  id: userId,
                  username,
                  role: userRole,
                  points: 0
                }
              }
            });
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erro no servidor' });
  }
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ 
      success: false, 
      message: 'Username e senha são obrigatórios' 
    });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) {
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
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      message: 'Login realizado com sucesso',
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          points: user.points
        }
      }
    });
  });
});

// ==================== ROTAS DE PARTIDAS ====================

// Buscar todas as partidas
app.get('/api/matches', authenticateToken, (req, res) => {
  db.all('SELECT * FROM matches ORDER BY date ASC', (err, matches) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Erro ao buscar partidas' });
    }
    res.json({ success: true, data: matches });
  });
});

// Buscar partida específica
app.get('/api/matches/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT * FROM matches WHERE id = ?', [id], (err, match) => {
    if (err || !match) {
      return res.status(404).json({ success: false, message: 'Partida não encontrada' });
    }
    res.json({ success: true, data: match });
  });
});

// ==================== ROTAS ADMIN - GERENCIAR PARTIDAS ====================

// Atualizar resultado de uma partida (ADMIN ONLY)
app.put('/api/admin/matches/:id/result', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { teamAScore, teamBScore } = req.body;

  if (teamAScore === undefined || teamBScore === undefined) {
    return res.status(400).json({ 
      success: false, 
      message: 'Scores são obrigatórios' 
    });
  }

  db.run(
    `UPDATE matches 
     SET teamAScore = ?, teamBScore = ?, status = 'played', updated_at = CURRENT_TIMESTAMP 
     WHERE id = ?`,
    [teamAScore, teamBScore, id],
    function(err) {
      if (err) {
        return res.status(500).json({ success: false, message: 'Erro ao atualizar partida' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ success: false, message: 'Partida não encontrada' });
      }

      // Calcular pontos dos palpites
      calculateBetPoints(id);

      // Buscar partida atualizada
      db.get('SELECT * FROM matches WHERE id = ?', [id], (err, match) => {
        res.json({
          success: true,
          message: 'Resultado atualizado com sucesso',
          data: match
        });
      });
    }
  );
});

// Criar nova partida (ADMIN ONLY)
app.post('/api/admin/matches', authenticateToken, requireAdmin, (req, res) => {
  const { id, teamA, teamB, date } = req.body;

  if (!id || !teamA || !teamB || !date) {
    return res.status(400).json({ 
      success: false, 
      message: 'Todos os campos são obrigatórios' 
    });
  }

  db.run(
    'INSERT INTO matches (id, teamA, teamB, date) VALUES (?, ?, ?, ?)',
    [id, teamA, teamB, date],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ success: false, message: 'Partida já existe' });
        }
        return res.status(500).json({ success: false, message: 'Erro ao criar partida' });
      }

      db.get('SELECT * FROM matches WHERE id = ?', [id], (err, match) => {
        res.json({
          success: true,
          message: 'Partida criada com sucesso',
          data: match
        });
      });
    }
  );
});

// Gerar token de acesso (ADMIN ONLY)
app.post('/api/admin/tokens', authenticateToken, requireAdmin, (req, res) => {
  const { is_admin } = req.body;
  const token = `TOKEN_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  db.run(
    'INSERT INTO access_tokens (token, is_admin) VALUES (?, ?)',
    [token, is_admin ? 1 : 0],
    function(err) {
      if (err) {
        return res.status(500).json({ success: false, message: 'Erro ao gerar token' });
      }

      res.json({
        success: true,
        message: 'Token gerado com sucesso',
        data: {
          token,
          is_admin: !!is_admin,
          type: is_admin ? 'ADMIN' : 'USER'
        }
      });
    }
  );
});

// Listar todos os tokens (ADMIN ONLY)
app.get('/api/admin/tokens', authenticateToken, requireAdmin, (req, res) => {
  db.all(
    `SELECT t.*, u.username as used_by_username 
     FROM access_tokens t 
     LEFT JOIN users u ON t.used_by = u.id 
     ORDER BY t.created_at DESC`,
    (err, tokens) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Erro ao buscar tokens' });
      }
      res.json({ success: true, data: tokens });
    }
  );
});

// ==================== ROTAS DE PALPITES ====================

// Buscar palpites do usuário
app.get('/api/bets/user', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.all(
    'SELECT * FROM bets WHERE user_id = ?',
    [userId],
    (err, bets) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Erro ao buscar palpites' });
      }

      // Transformar array em objeto {matchId: bet}
      const betsObj = {};
      bets.forEach(bet => {
        betsObj[bet.match_id] = {
          matchId: bet.match_id,
          teamAScore: bet.teamAScore,
          teamBScore: bet.teamBScore,
          points: bet.points,
          createdAt: bet.created_at
        };
      });

      res.json({ success: true, data: betsObj });
    }
  );
});

// Criar ou atualizar palpite
app.post('/api/bets', authenticateToken, (req, res) => {
  const { matchId, teamAScore, teamBScore } = req.body;
  const userId = req.user.id;

  if (!matchId || teamAScore === undefined || teamBScore === undefined) {
    return res.status(400).json({ 
      success: false, 
      message: 'Todos os campos são obrigatórios' 
    });
  }

  // Verificar se a partida existe e ainda não foi jogada
  db.get('SELECT * FROM matches WHERE id = ? AND status = "upcoming"', [matchId], (err, match) => {
    if (err || !match) {
      return res.status(400).json({ 
        success: false, 
        message: 'Partida não disponível para palpites' 
      });
    }

    // Insert or update
    db.run(
      `INSERT INTO bets (user_id, match_id, teamAScore, teamBScore) 
       VALUES (?, ?, ?, ?)
       ON CONFLICT(user_id, match_id) 
       DO UPDATE SET teamAScore = ?, teamBScore = ?, updated_at = CURRENT_TIMESTAMP`,
      [userId, matchId, teamAScore, teamBScore, teamAScore, teamBScore],
      function(err) {
        if (err) {
          return res.status(500).json({ success: false, message: 'Erro ao salvar palpite' });
        }

        res.json({
          success: true,
          message: 'Palpite salvo com sucesso',
          data: {
            matchId,
            teamAScore,
            teamBScore,
            createdAt: new Date().toISOString()
          }
        });
      }
    );
  });
});

// ==================== RANKING ====================

app.get('/api/ranking', authenticateToken, (req, res) => {
  db.all(
    `SELECT id, username, points, role
     FROM users 
     ORDER BY points DESC, username ASC`,
    (err, users) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Erro ao buscar ranking' });
      }

      const ranking = users.map((user, index) => ({
        position: index + 1,
        username: user.username,
        points: user.points,
        isAdmin: user.role === 'admin'
      }));

      res.json({ success: true, data: ranking });
    }
  );
});

// ==================== USUÁRIO ====================

app.get('/api/user/me', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, username, points, role FROM users WHERE id = ?',
    [req.user.id],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
      }

      res.json({
        success: true,
        data: {
          username: user.username,
          points: user.points,
          role: user.role
        }
      });
    }
  );
});

// ==================== FUNÇÕES AUXILIARES ====================

// Calcular pontos dos palpites após resultado
function calculateBetPoints(matchId) {
  db.get('SELECT * FROM matches WHERE id = ?', [matchId], (err, match) => {
    if (err || !match || match.teamAScore === null) return;

    db.all('SELECT * FROM bets WHERE match_id = ?', [matchId], (err, bets) => {
      if (err) return;

      bets.forEach(bet => {
        const points = calculatePoints(
          match.teamAScore,
          match.teamBScore,
          bet.teamAScore,
          bet.teamBScore
        );

        // Atualizar pontos do palpite
        db.run('UPDATE bets SET points = ? WHERE id = ?', [points, bet.id]);

        // Atualizar pontos totais do usuário
        db.run(
          'UPDATE users SET points = (SELECT SUM(points) FROM bets WHERE user_id = ?) WHERE id = ?',
          [bet.user_id, bet.user_id]
        );
      });
    });
  });
}

// Lógica de cálculo de pontos
function calculatePoints(actualA, actualB, betA, betB) {
  // Placar exato
  if (betA === actualA && betB === actualB) {
    return actualA === actualB ? 15 : 25;
  }

  // Acertou vencedor
  if ((betA > betB && actualA > actualB) || (betA < betB && actualA < actualB)) {
    return 10;
  }

  // Acertou empate
  if (betA === betB && actualA === actualB) {
    return 10;
  }

  return 0;
}

// ==================== SERVIDOR ====================

app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
  console.log(`🔑 Token Admin: ${ADMIN_TOKEN}`);
  console.log(`📊 Acesse: http://localhost:${PORT}`);
});
