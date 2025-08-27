const express = require("express");
const cors = require("cors");
const db = require("./db");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Rota para salvar pontuação
app.post("/pontuacao", (req, res) => {
  const { nome, pontos } = req.body;

  if (!nome || !pontos) return res.status(400).json({ msg: "Dados incompletos" });

  const sql = "INSERT INTO ranking (nome, pontos) VALUES (?, ?)";
  db.query(sql, [nome, pontos], (err, result) => {
    if (err) return res.status(500).json({ msg: err });
    res.json({ msg: "Pontuação salva!" });
  });
});

// Rota para listar ranking
app.get("/ranking", (req, res) => {
  const sql = "SELECT nome, pontos FROM ranking ORDER BY pontos DESC LIMIT 10";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ msg: err });
    res.json(results);
  });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
