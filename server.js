const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Configurações
const API_KEY = 'a1f6d24cd4b844e082f1d4b4507ccb62'; // Sua API Key
const API_URL = 'https://api.football-data.org/v4';
const COMPETITION_CODE = 'CL'; // Champions League

// Middleware
app.use(cors());
app.use(bodyParser.json());

// ==========================================
// BANCO DE DADOS EM MEMÓRIA (Simulação)
// Em produção real, substitua por MongoDB/Postgres
// ==========================================
const db = {
  users: [],       // { id, username, password, token, points, isAdmin }
  bets: [],        // { id, userId, matchId, teamAScore, teamBScore, createdAt }
  tokens: ['CHAMPIONS2024', 'BOLAOVIP'], // Tokens de acesso válidos para cadastro
  matchesCache: null,
  lastCacheTime: 0
};

// ==========================================
// FUNÇÕES AUXILIARES
// ==========================================

// Buscar partidas da API Externa (com Cache de 5 minutos)
async function fetchMatches() {
  const now = Date.now();
  // Se o cache tem menos de 5 minutos (300000ms), retorna cache
  if (db.matchesCache && (now - db.lastCacheTime < 300000)) {
    console.log('Retornando partidas do cache...');
    return db.matchesCache;
  }

  console.log('Buscando partidas da API externa...');
  try {
    const response = await axios.get(`${API_URL}/competitions/${COMPETITION_CODE}/matches`, {
      headers: { 'X-Auth-Token': API_KEY }
    });

    const matches = response.data.matches.map(m => ({
      id: m.id.toString(),
      teamA: m.homeTeam.shortName || m.homeTeam.name,
      teamB: m.awayTeam.shortName || m.awayTeam.name,
      date: m.utcDate,
      status: m.status === 'FINISHED' ? 'played' : 'upcoming',
      teamAScore: m.score.fullTime.home,
      teamBScore: m.score.fullTime.away,
      stage: m.stage
    }));

    db.matchesCache = matches;
    db.lastCacheTime = now;
    return matches;
  } catch (error) {
    console.error('Erro ao buscar na API:', error.message);
    return db.matchesCache || []; // Retorna cache antigo se falhar
  }
}

// Calcular Pontos
function calculatePoints(match, bet) {
  if (match.status !== 'played' || match.teamAScore === null) return 0;
  
  const realA = match.teamAScore;
  const realB = match.teamBScore;
  const betA = bet.teamAScore;
  const betB = bet.teamBScore;

  // Placar Exato (25 pts)
  if (realA === betA && realB === betB) {
    // Empate exato vale 15 pts no seu app, vitória exata vale 25
    if (realA === realB) return 15; 
    return 25;
  }

  // Acertou Vencedor ou Empate (sem placar exato)
  const realWinner = realA > realB ? 'A' : (realB > realA ? 'B' : 'DRAW');
  const betWinner = betA > betB ? 'A' : (betB > betA ? 'B' : 'DRAW');

  if (realWinner === betWinner) {
    return 10;
  }

  return 0;
}

// Atualizar Ranking
async function updateRanking() {
  const matches = await fetchMatches();
  
  db.users.forEach(user => {
    let totalPoints = 0;
    const userBets = db.bets.filter(b => b.userId === user.id);
    
    userBets.forEach(bet => {
      const match = matches.find(m => m.id === bet.matchId);
      if (match) {
        totalPoints += calculatePoints(match, bet);
      }
    });
    
    user.points = totalPoints;
  });
}

// ==========================================
// ROTAS - AUTH
// ==========================================

app.post('/api/auth/register', (req, res) => {
  const { username, password, access_token } = req.body;

  if (!db.tokens.includes(access_token)) {
    return res.status(400).json({ success: false, message: 'Token de acesso inválido.' });
  }

  if (db.users.find(u => u.username === username)) {
    return res.status(400).json({ success: false, message: 'Usuário já existe.' });
  }

  const newUser = {
    id: uuidv4(),
    username,
    password, // Em produção, use hash (bcrypt)
    token: uuidv4(), // Token de sessão simples
    points: 0,
    isAdmin: false
  };

  db.users.push(newUser);
  res.json({ success: true, data: { token: newUser.token, user: newUser } });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.users.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });
  }

  // Atualiza pontos ao logar para garantir
  updateRanking();

  res.json({ success: true, data: { token: user.token, user } });
});

app.get('/api/user/me', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const user = db.users.find(u => u.token === token);
  
  if (user) {
    res.json({ success: true, data: user });
  } else {
    res.status(401).json({ success: false, message: 'Não autorizado' });
  }
});

// ==========================================
// ROTAS - PARTIDAS E PALPITES
// ==========================================

app.get('/api/matches', async (req, res) => {
  const matches = await fetchMatches();
  res.json({ success: true, data: matches });
});

app.get('/api/bets/user', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const user = db.users.find(u => u.token === token);

  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  const userBets = db.bets.filter(b => b.userId === user.id);
  const betsMap = {};
  
  userBets.forEach(b => {
    betsMap[b.matchId] = {
      matchId: b.matchId,
      teamAScore: b.teamAScore,
      teamBScore: b.teamBScore,
      createdAt: b.createdAt
    };
  });

  res.json({ success: true, data: betsMap });
});

app.post('/api/bets', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const user = db.users.find(u => u.token === token);
  const { matchId, teamAScore, teamBScore } = req.body;

  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  // Verifica se a partida já começou (opcional, mas recomendado)
  // ...

  // Remove aposta antiga se existir
  const existingBetIndex = db.bets.findIndex(b => b.userId === user.id && b.matchId === matchId);
  if (existingBetIndex !== -1) {
    db.bets.splice(existingBetIndex, 1);
  }

  const newBet = {
    id: uuidv4(),
    userId: user.id,
    matchId,
    teamAScore,
    teamBScore,
    createdAt: new Date().toISOString()
  };

  db.bets.push(newBet);
  res.json({ success: true, message: 'Palpite salvo com sucesso!' });
});

// ==========================================
// ROTAS - RANKING
// ==========================================

app.get('/api/ranking', async (req, res) => {
  await updateRanking(); // Recalcula antes de enviar

  const sortedUsers = [...db.users].sort((a, b) => b.points - a.points);
  
  const ranking = sortedUsers.map((u, index) => ({
    username: u.username,
    points: u.points,
    position: index + 1
  }));

  res.json({ success: true, data: ranking });
});

// ==========================================
// ROTAS - ADMIN (Opcional/Simplificado)
// ==========================================

app.post('/api/admin/tokens', (req, res) => {
  const { token } = req.body;
  db.tokens.push(token);
  res.json({ success: true, data: db.tokens });
});

// Iniciar Servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
