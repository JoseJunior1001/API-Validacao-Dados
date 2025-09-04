const express = require("express");
const cors = require("cors");
const db = require("./db");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Salvar pontuação
app.post("/pontuacao", async (req, res) => {
  const { nome, pontos } = req.body;
  if (!nome || !pontos) return res.status(400).json({ msg: "Dados incompletos" });

  try {
    await db.query("INSERT INTO ranking (nome, pontos) VALUES ($1, $2)", [nome, pontos]);
    res.json({ msg: "Pontuação salva!" });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

// Listar ranking
app.get("/ranking", async (req, res) => {
  try {
    const result = await db.query("SELECT nome, pontos FROM ranking ORDER BY pontos DESC LIMIT 10");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
